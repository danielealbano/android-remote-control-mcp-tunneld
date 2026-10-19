package store

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// TestIsNotFound_BucketErrorsNotMatched pins the strict key-absence semantics: only NoSuchKey / the
// HeadObject NotFound are key absence; a bucket-level 404 (NoSuchBucket) and transport errors are NOT,
// so a bucket outage never reads as name_unknown.
func TestIsNotFound_BucketErrorsNotMatched(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"NoSuchKey type", &types.NoSuchKey{}, true},
		{"NotFound type", &types.NotFound{}, true},
		{"NoSuchKey apierror", &smithy.GenericAPIError{Code: "NoSuchKey"}, true},
		{"HeadObject NotFound apierror", &smithy.GenericAPIError{Code: "NotFound"}, true},
		{"NoSuchBucket apierror", &smithy.GenericAPIError{Code: "NoSuchBucket"}, false},
		{"transport error", errors.New("dial tcp: connection refused"), false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Errorf("isNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
