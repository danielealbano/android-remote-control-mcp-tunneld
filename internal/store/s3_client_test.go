package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// TestS3ClientSingleAttempt covers the claim
// invariant: a failing PUT is NEVER silently replayed by SDK retries (a timed-out claim PUT replayed
// later would be a zombie write).
func TestS3ClientSingleAttempt(t *testing.T) {
	var puts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		// A retryable-by-default S3 error: with retries enabled the SDK would replay the PUT.
		http.Error(w, `<Error><Code>InternalError</Code></Error>`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	st, err := NewS3Store(context.Background(), S3Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "test",
		AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := st.PutName(ctx, "abc", NameRecord{Schema: 1}); err == nil {
		t.Fatal("a 500 PUT must surface an error")
	}
	if got := puts.Load(); got != 1 {
		t.Fatalf("the S3 client must attempt each request EXACTLY once (no retries), got %d PUTs", got)
	}
}

type closeFailBody struct{ io.Reader }

func (closeFailBody) Close() error { return errors.New("body close failed") }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestS3Store_GetName_ReturnsBodyCloseError(t *testing.T) {
	cli := s3.New(s3.Options{
		Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("k", "s", ""),
		BaseEndpoint: aws.String("http://s3.example.test"), UsePathStyle: true,
		RetryMaxAttempts: 1, Retryer: aws.NopRetryer{},
		HTTPClient: doerFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
				Body: closeFailBody{strings.NewReader(`{"schema":1}`)}, Request: r,
			}, nil
		}),
	})
	st := &S3Store{cli: cli, bucket: "test"}
	rec, err := st.GetName(context.Background(), "abc")
	if err == nil || !strings.Contains(err.Error(), `store: close name "abc" body: body close failed`) {
		t.Fatalf("GetName = (%+v, %v), want the body close error", rec, err)
	}
}

func TestS3Store_PutConnLogFile_UsesUncappedLogClient(t *testing.T) {
	t.Parallel()
	st, err := NewS3Store(context.Background(), S3Config{
		Endpoint: "http://s3.example.test", Region: "us-east-1", Bucket: "test",
		AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := st.cli.Options().HTTPClient.(*awshttp.BuildableClient); !ok || c.GetTimeout() != 30*time.Second {
		t.Fatalf("the general S3 client must keep its 30 s cap, got %T", st.cli.Options().HTTPClient)
	}
	if c, ok := st.logHTTP.(*awshttp.BuildableClient); !ok || c.GetTimeout() != 0 {
		t.Fatalf("the conn-log client must have no overall timeout (the spool sets a size-scaled deadline), got %T", st.logHTTP)
	}

	var general, logs atomic.Int64
	st.cli = s3.New(st.cli.Options(), func(o *s3.Options) {
		o.HTTPClient = doerFunc(func(*http.Request) (*http.Response, error) {
			general.Add(1)
			return nil, errors.New("the capped general client must not carry conn-log uploads")
		})
	})
	var req *http.Request
	var body []byte
	st.logHTTP = doerFunc(func(r *http.Request) (*http.Response, error) {
		logs.Add(1)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		req, body = r, raw
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	payload := `{"schema":1}` + "\n"
	key := "tunnel-logs/2026/10/13/20261013T100000.000000000Z-00000000000000aa.jsonl"
	if err := st.PutConnLogFile(context.Background(), key, strings.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if general.Load() != 0 || logs.Load() != 1 {
		t.Fatalf("the upload must go through the conn-log client only, general=%d logs=%d", general.Load(), logs.Load())
	}
	if req.Method != http.MethodPut || req.URL.Path != "/test/"+key || req.ContentLength != int64(len(payload)) ||
		req.Header.Get("Content-Type") != "application/x-ndjson" || string(body) != payload {
		t.Fatalf("PUT %s cl=%d type=%q body=%q, want PUT /test/%s cl=%d type=application/x-ndjson body=%q",
			req.URL.Path, req.ContentLength, req.Header.Get("Content-Type"), body, key, len(payload), payload)
	}
}

func TestS3Store_PutPhonesSeenFile(t *testing.T) {
	t.Parallel()
	const key = "phones-seen/2026/10/13/00000000000000aa.json"
	payload := `{"schema":1,"node":"00000000000000aa","day":"2026-10-13","phones":{}}`
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "uploaded through the uncapped log client", status: http.StatusOK},
		{name: "refused by S3", status: http.StatusForbidden, wantErr: `store: put phones-seen file "` + key + `"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newFakeS3Store(t, func(*http.Request, []byte) s3Reply {
				t.Error("the capped general client must not carry phones-seen uploads")
				return s3Reply{status: http.StatusInternalServerError}
			})
			var req *http.Request
			var body []byte
			st.logHTTP = doerFunc(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				req, body = r, raw
				reply := ""
				if tc.status != http.StatusOK {
					reply = s3ErrorXML("AccessDenied")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/xml"}},
					Body: io.NopCloser(strings.NewReader(reply)), Request: r}, nil
			})
			err := st.PutPhonesSeenFile(context.Background(), key, strings.NewReader(payload), int64(len(payload)))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PutPhonesSeenFile error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != http.MethodPut || req.URL.Path != "/test/"+key || req.ContentLength != int64(len(payload)) ||
				req.Header.Get("Content-Type") != "application/json" || string(body) != payload {
				t.Fatalf("PUT %s cl=%d type=%q body=%q, want PUT /test/%s cl=%d type=application/json body=%q",
					req.URL.Path, req.ContentLength, req.Header.Get("Content-Type"), body, key, len(payload), payload)
			}
		})
	}
}

type s3Reply struct {
	status int
	body   string
}

func s3ErrorXML(code string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>injected</Message></Error>`
}

func listXML(next string, keys ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>test</Name>`)
	fmt.Fprintf(&b, "<KeyCount>%d</KeyCount><IsTruncated>%t</IsTruncated>", len(keys), next != "")
	if next != "" {
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", next)
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key></Contents>", k)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func newFakeS3Store(t *testing.T, serve func(r *http.Request, body []byte) s3Reply) *S3Store {
	t.Helper()
	st, err := NewS3Store(context.Background(), S3Config{
		Endpoint: "http://s3.example.test", Region: "us-east-1", Bucket: "test",
		AccessKey: "k", SecretKey: "s", ForcePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st.cli = s3.New(st.cli.Options(), func(o *s3.Options) {
		o.HTTPClient = doerFunc(func(r *http.Request) (*http.Response, error) {
			var body []byte
			if r.Body != nil {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				body = raw
			}
			rep := serve(r, body)
			return &http.Response{
				StatusCode: rep.status, Header: http.Header{"Content-Type": {"application/xml"}},
				Body: io.NopCloser(strings.NewReader(rep.body)), Request: r,
			}, nil
		})
	})
	return st
}

func TestS3Store_PutAttestation(t *testing.T) {
	t.Parallel()
	a := Attestation{TS: time.Unix(1_700_000_000, 0).UTC(), Kind: AttestationKindIssue, AttestChainPEM: "CHAIN"}
	keyRE := regexp.MustCompile(`^/test/attestations/abc/20231114T221320\.000000000Z-[0-9a-f]{4}\.json$`)
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "stored in the name's history", status: http.StatusOK},
		{name: "refused by S3", status: http.StatusForbidden, wantErr: `store: put attestation of "abc"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var req *http.Request
			var body []byte
			st := newFakeS3Store(t, func(r *http.Request, b []byte) s3Reply {
				req, body = r, b
				if tc.status != http.StatusOK {
					return s3Reply{status: tc.status, body: s3ErrorXML("AccessDenied")}
				}
				return s3Reply{status: http.StatusOK}
			})
			err := st.PutAttestation(context.Background(), "abc", a)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PutAttestation error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != http.MethodPut || !keyRE.MatchString(req.URL.Path) || req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("request = %s %s (type %q), want PUT of a JSON object matching %s", req.Method, req.URL.Path, req.Header.Get("Content-Type"), keyRE)
			}
			var back Attestation
			if err := json.Unmarshal(body, &back); err != nil || back != a {
				t.Fatalf("stored body %q decodes to %+v (%v), want %+v", body, back, err, a)
			}
		})
	}
}

func TestS3Store_PruneAttestations(t *testing.T) {
	t.Parallel()
	const prefix = "attestations/abc/"
	k := func(i int) string { return fmt.Sprintf("%s2023111%dT000000.000000000Z-00aa.json", prefix, i) }
	tests := []struct {
		name        string
		keep        int
		pages       [][]string
		listStatus  int
		deleteCode  map[string]string
		wantDeleted []string
		wantErr     string
		notInErr    string
	}{
		{name: "keep below 1 is refused before any request", keep: 0, wantErr: "keep 0 is below 1"},
		{name: "no more than keep: nothing is deleted", keep: 2, pages: [][]string{{k(1), k(2)}}},
		{name: "the oldest are deleted across pages", keep: 2, pages: [][]string{{k(3), k(1)}, {k(4), k(2)}}, wantDeleted: []string{k(1), k(2)}},
		{name: "a failed list deletes nothing", keep: 1, listStatus: http.StatusForbidden, wantErr: `store: list attestations of "abc"`},
		{
			name: "a failed delete is reported and the others still run", keep: 1,
			pages:       [][]string{{k(1), k(2), k(3), k(4)}},
			deleteCode:  map[string]string{k(1): "AccessDenied", k(2): "NoSuchKey"},
			wantDeleted: []string{k(1), k(2), k(3)},
			wantErr:     `store: delete attestation "` + k(1) + `"`,
			notInErr:    k(2),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var requests int
			var deleted []string
			st := newFakeS3Store(t, func(r *http.Request, _ []byte) s3Reply {
				requests++
				switch r.Method {
				case http.MethodGet:
					q := r.URL.Query()
					if q.Get("list-type") != "2" || q.Get("prefix") != prefix {
						return s3Reply{status: http.StatusBadRequest, body: s3ErrorXML("InvalidRequest")}
					}
					if tc.listStatus != 0 {
						return s3Reply{status: tc.listStatus, body: s3ErrorXML("AccessDenied")}
					}
					page := 0
					if tok := q.Get("continuation-token"); tok != "" {
						if _, err := fmt.Sscanf(tok, "page-%d", &page); err != nil || page >= len(tc.pages) {
							return s3Reply{status: http.StatusBadRequest, body: s3ErrorXML("InvalidArgument")}
						}
					}
					next := ""
					if page+1 < len(tc.pages) {
						next = fmt.Sprintf("page-%d", page+1)
					}
					return s3Reply{status: http.StatusOK, body: listXML(next, tc.pages[page]...)}
				case http.MethodDelete:
					key := strings.TrimPrefix(r.URL.Path, "/test/")
					deleted = append(deleted, key)
					switch tc.deleteCode[key] {
					case "AccessDenied":
						return s3Reply{status: http.StatusForbidden, body: s3ErrorXML("AccessDenied")}
					case "NoSuchKey":
						return s3Reply{status: http.StatusNotFound, body: s3ErrorXML("NoSuchKey")}
					}
					return s3Reply{status: http.StatusNoContent}
				}
				return s3Reply{status: http.StatusBadRequest, body: s3ErrorXML("InvalidRequest")}
			})
			err := st.PruneAttestations(context.Background(), "abc", tc.keep)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("PruneAttestations error = %v, want none", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("PruneAttestations error = %v, want %q", err, tc.wantErr)
			case tc.notInErr != "" && strings.Contains(err.Error(), tc.notInErr):
				t.Fatalf("an already-missing key must not be reported, got %v", err)
			}
			if !slices.Equal(deleted, tc.wantDeleted) {
				t.Fatalf("deleted %v, want %v", deleted, tc.wantDeleted)
			}
			if tc.keep < 1 && requests != 0 {
				t.Fatalf("a refused keep must not reach S3, got %d requests", requests)
			}
		})
	}
}
