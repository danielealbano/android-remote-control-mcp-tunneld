package bucket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const maxObjectBytes = 64 << 20

var ErrNotFound = errors.New("object not found")

type Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
}

type S3 struct {
	cli    *s3.Client
	bucket string
}

func New(cfg Config) *S3 {
	cli := s3.New(s3.Options{
		Region:       cfg.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: cfg.ForcePathStyle,
		HTTPClient:   awshttp.NewBuildableClient().WithTimeout(30 * time.Second),
	})
	return &S3{cli: cli, bucket: cfg.Bucket}
}

type Object struct {
	Key          string
	LastModified time.Time
}

func (b *S3) List(ctx context.Context, prefix string) ([]string, error) {
	objs, err := b.ListObjects(ctx, prefix)
	if err != nil {
		return nil, err
	}
	keys := make([]string, len(objs))
	for i, o := range objs {
		keys[i] = o.Key
	}
	return keys, nil
}

func (b *S3) ListObjects(ctx context.Context, prefix string) ([]Object, error) {
	var objs []Object
	pages := s3.NewListObjectsV2Paginator(b.cli, &s3.ListObjectsV2Input{Bucket: &b.bucket, Prefix: aws.String(prefix)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			objs = append(objs, Object{Key: aws.ToString(obj.Key), LastModified: aws.ToTime(obj.LastModified)})
		}
	}
	return objs, nil
}

func (b *S3) Get(ctx context.Context, key string) (_ []byte, err error) {
	out, err := b.cli.GetObject(ctx, &s3.GetObjectInput{Bucket: &b.bucket, Key: aws.String(key)})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	defer func() {
		if cerr := out.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close %s: %w", key, cerr))
		}
	}()
	body, err := io.ReadAll(io.LimitReader(out.Body, maxObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	if len(body) > maxObjectBytes {
		return nil, fmt.Errorf("read %s: larger than %d bytes", key, maxObjectBytes)
	}
	return body, nil
}

func (b *S3) Put(ctx context.Context, key string, body []byte) error {
	_, err := b.cli.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &b.bucket,
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

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
