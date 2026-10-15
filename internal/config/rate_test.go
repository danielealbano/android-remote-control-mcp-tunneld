package config

import (
	"testing"
	"time"
)

func TestParseRate_Variants(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Rate
		wantErr bool
	}{
		{name: "count over period", in: "50/168h", want: Rate{Count: 50, Period: 168 * time.Hour, Burst: 50}},
		{name: "explicit burst", in: "200/1h:40", want: Rate{Count: 200, Period: time.Hour, Burst: 40}},
		{name: "surrounding spaces", in: "  120/1m ", want: Rate{Count: 120, Period: time.Minute, Burst: 120}},
		{name: "no slash", in: "50", wantErr: true},
		{name: "zero count", in: "0/1h", wantErr: true},
		{name: "negative count", in: "-1/1h", wantErr: true},
		{name: "non-integer count", in: "x/1h", wantErr: true},
		{name: "bad period", in: "5/soon", wantErr: true},
		{name: "zero period", in: "5/0s", wantErr: true},
		{name: "zero burst", in: "5/1h:0", wantErr: true},
		{name: "non-integer burst", in: "5/1h:x", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRate(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRate(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("ParseRate(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}
