package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3Config configures the S3-backed store.
type S3Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
}

// S3Store is the plain-S3 backend. It uses ONLY GetObject/PutObject/DeleteObject — no conditional
// writes, no ETags. Registry writes go through a client with SDK auto-retries DISABLED (a timed-out
// claim PUT must never be silently replayed into a zombie write); the caller's ctx carries the deadline.
type S3Store struct {
	cli    *s3.Client
	bucket string
}

var _ Store = (*S3Store)(nil)

// NewS3Store builds the backend. Static credentials + a custom endpoint make it work identically
// against any plain S3 provider or MinIO (force-path-style).
func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	creds := credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
	cli := s3.New(s3.Options{
		Region:       cfg.Region,
		Credentials:  creds,
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: cfg.ForcePathStyle,
		// Retries DISABLED for every request: the write-verify claim depends on a timed-out PUT NOT
		// being replayed, and the LWW/GET/DELETE paths handle their own errors.
		RetryMaxAttempts: 1,
		Retryer:          aws.NopRetryer{},
		// A hard per-request HTTP timeout: a hung S3 endpoint must never pin a caller (teardown paths
		// write conn logs without their own deadline). A caller ctx with a SHORTER deadline still wins.
		HTTPClient: awshttp.NewBuildableClient().WithTimeout(30 * time.Second),
	})
	return &S3Store{cli: cli, bucket: cfg.Bucket}, nil
}

func nameKey(name string) string { return "names/" + name }

// GetName reads and decodes the registry object; NoSuchKey → ErrNotFound.
func (s *S3Store) GetName(ctx context.Context, name string) (NameRecord, error) {
	out, err := s.cli.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: aws.String(nameKey(name))})
	if err != nil {
		if isNotFound(err) {
			return NameRecord{}, ErrNotFound
		}
		return NameRecord{}, fmt.Errorf("store: get name %q: %w", name, err)
	}
	defer func() { _ = out.Body.Close() }()
	var rec NameRecord
	if err := json.NewDecoder(out.Body).Decode(&rec); err != nil {
		return NameRecord{}, fmt.Errorf("store: decode name %q: %w", name, err)
	}
	return rec, nil
}

// PutName writes the record with a plain PutObject (no conditional headers, retries disabled).
func (s *S3Store) PutName(ctx context.Context, name string, rec NameRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("store: marshal name %q: %w", name, err)
	}
	_, err = s.cli.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         aws.String(nameKey(name)),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("store: put name %q: %w", name, err)
	}
	return nil
}

// DeleteName removes the registry object.
func (s *S3Store) DeleteName(ctx context.Context, name string) error {
	_, err := s.cli.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: aws.String(nameKey(name))})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("store: delete name %q: %w", name, err)
	}
	return nil
}

// PutConnLog writes one connection-log event object.
func (s *S3Store) PutConnLog(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("store: marshal conn log: %w", err)
	}
	_, err = s.cli.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         aws.String(LogKey(ev)),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("store: put conn log: %w", err)
	}
	return nil
}

// PutRejectedEnrollment writes one rejected-enrollment evidence object.
func (s *S3Store) PutRejectedEnrollment(ctx context.Context, ev RejectedEnrollment) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("store: marshal rejected enrollment: %w", err)
	}
	_, err = s.cli.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.bucket,
		Key:         aws.String(RejectedKey(ev)),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("store: put rejected enrollment: %w", err)
	}
	return nil
}

// EnsureLifecycles upserts tunneld's two expiration rules by ID, PRESERVING any operator-added rules
// on the bucket (a blanket replace would silently delete them at every boot): tunnel-logs/ after
// connLogDays and rejected-enroll/ after rejectedDays.
func (s *S3Store) EnsureLifecycles(ctx context.Context, connLogDays, rejectedDays int) error {
	ours := []types.LifecycleRule{
		{
			ID:         aws.String("tunnel-logs-expire"),
			Status:     types.ExpirationStatusEnabled,
			Filter:     &types.LifecycleRuleFilter{Prefix: aws.String("tunnel-logs/")},
			Expiration: &types.LifecycleExpiration{Days: aws.Int32(int32(connLogDays))},
		},
		{
			ID:         aws.String("rejected-enroll-expire"),
			Status:     types.ExpirationStatusEnabled,
			Filter:     &types.LifecycleRuleFilter{Prefix: aws.String("rejected-enroll/")},
			Expiration: &types.LifecycleExpiration{Days: aws.Int32(int32(rejectedDays))},
		},
	}
	var merged []types.LifecycleRule
	cur, err := s.cli.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: &s.bucket})
	switch {
	case err == nil:
		for _, r := range cur.Rules {
			if r.ID == nil || (*r.ID != "tunnel-logs-expire" && *r.ID != "rejected-enroll-expire") {
				merged = append(merged, r)
			}
		}
	case isNoLifecycle(err):
		// no configuration yet — start from empty
	default:
		return fmt.Errorf("store: read lifecycles: %w", err)
	}
	merged = append(merged, ours...)
	_, err = s.cli.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: &s.bucket, LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: merged},
	})
	if err != nil {
		return fmt.Errorf("store: ensure lifecycles: %w", err)
	}
	return nil
}

// isNoLifecycle matches the absent-lifecycle-configuration error.
func isNoLifecycle(err error) bool {
	ae, ok := errors.AsType[smithy.APIError](err)
	return ok && ae.ErrorCode() == "NoSuchLifecycleConfiguration"
}

// isNotFound reports whether err is a definitive KEY-absence (NoSuchKey / HeadObject NotFound). A
// bucket-level or transport 404 (e.g. NoSuchBucket) is NOT key absence: callers map non-not-found
// errors to retryable failures, and a bucket outage must never read as name_unknown.
func isNotFound(err error) bool {
	if _, ok := errors.AsType[*types.NoSuchKey](err); ok {
		return true
	}
	if _, ok := errors.AsType[*types.NotFound](err); ok {
		return true
	}
	if ae, ok := errors.AsType[smithy.APIError](err); ok && (ae.ErrorCode() == "NoSuchKey" || ae.ErrorCode() == "NotFound") {
		return true
	}
	return false
}
