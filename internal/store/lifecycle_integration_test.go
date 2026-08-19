//go:build integration

package store_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// TestEnsureLifecycles_MergePreservesForeignRules verifies against a real MinIO backend that a boot-time
// EnsureLifecycles UPSERTS tunneld's two rules while PRESERVING an operator-added rule, and that a second
// run is idempotent (no duplication). The FIRST call runs against a bucket with NO lifecycle
// configuration, confirming the NoSuchLifecycleConfiguration error code the merge relies on is the one
// the backend actually returns; an operator override (replacing the whole config) is then merged back.
func TestEnsureLifecycles_MergePreservesForeignRules(t *testing.T) {
	s3URL, access, secret := tunneltest.StartMinIO(t)
	const bucket = "tunneld-lifecycle"
	tunneltest.EnsureS3Bucket(t, s3URL, access, secret, bucket)
	ctx := context.Background()

	raw := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(access, secret, ""),
		BaseEndpoint: aws.String(s3URL),
		UsePathStyle: true,
	})

	st, err := store.NewS3Store(ctx, store.S3Config{
		Endpoint: s3URL, Region: "us-east-1", Bucket: bucket, AccessKey: access, SecretKey: secret, ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// First run on a lifecycle-less bucket: exercises the NoSuchLifecycleConfiguration branch for real
	// and lands exactly the two tunneld rules.
	if err := st.EnsureLifecycles(ctx, 90, 30); err != nil {
		t.Fatalf("first EnsureLifecycles (empty bucket): %v", err)
	}
	assertLifecycleRules(t, raw, bucket, map[string]int32{"tunnel-logs-expire": 90, "rejected-enroll-expire": 30})

	// An operator override replaces the WHOLE configuration with their single rule (the destructive
	// pattern the merge must survive): the next boot must merge tunneld's rules back while keeping it.
	if _, err := raw.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{Rules: []types.LifecycleRule{{
			ID:         aws.String("operator-archive"),
			Status:     types.ExpirationStatusEnabled,
			Filter:     &types.LifecycleRuleFilter{Prefix: aws.String("operator-data/")},
			Expiration: &types.LifecycleExpiration{Days: aws.Int32(7)},
		}}},
	}); err != nil {
		t.Fatalf("seed operator rule: %v", err)
	}

	want := map[string]int32{"operator-archive": 7, "tunnel-logs-expire": 90, "rejected-enroll-expire": 30}

	if err := st.EnsureLifecycles(ctx, 90, 30); err != nil {
		t.Fatalf("second EnsureLifecycles (merge): %v", err)
	}
	assertLifecycleRules(t, raw, bucket, want)

	// A third run is idempotent: still exactly those three rules (operator rule intact, no duplication).
	if err := st.EnsureLifecycles(ctx, 90, 30); err != nil {
		t.Fatalf("third EnsureLifecycles: %v", err)
	}
	assertLifecycleRules(t, raw, bucket, want)
}

func assertLifecycleRules(t *testing.T, cli *s3.Client, bucket string, want map[string]int32) {
	t.Helper()
	out, err := cli.GetBucketLifecycleConfiguration(context.Background(), &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatalf("get lifecycles: %v", err)
	}
	got := map[string]int32{}
	for _, r := range out.Rules {
		if r.ID == nil || r.Expiration == nil || r.Expiration.Days == nil {
			t.Fatalf("unexpected lifecycle rule shape: %+v", r)
		}
		got[*r.ID] = *r.Expiration.Days
	}
	if len(got) != len(want) {
		t.Fatalf("lifecycle rule set = %v, want %v", got, want)
	}
	for id, days := range want {
		if got[id] != days {
			t.Errorf("rule %q days = %d, want %d", id, got[id], days)
		}
	}
}
