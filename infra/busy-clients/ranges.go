package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

const (
	maxRangeBytes    = 4 << 20
	outboundHeading  = `id="outbound-ip-addresses"`
	phasedOutHeading = `id="phased-out-ip-addresses"`
)

var codeElement = regexp.MustCompile(`<code>([^<]*)</code>`)

type openAIList struct {
	Prefixes []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func loadRanges(ctx context.Context, client *http.Client, logger *slog.Logger, openAI []string, anthropic string) ([]netip.Prefix, error) {
	if len(openAI) == 0 {
		return nil, errors.New("no OpenAI address list is set")
	}
	if anthropic == "" {
		return nil, errors.New("the Anthropic address page is not set")
	}
	var all []netip.Prefix
	for _, url := range openAI {
		body, err := fetch(ctx, client, url)
		if err != nil {
			return nil, err
		}
		var list openAIList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("decode the OpenAI address list %s: %w", url, err)
		}
		found := len(all)
		for _, p := range list.Prefixes {
			for _, s := range []string{p.IPv4, p.IPv6} {
				if s == "" {
					continue
				}
				pfx, err := parseRange(s)
				if err != nil {
					return nil, fmt.Errorf("read the range %q of the OpenAI address list %s: %w", s, url, err)
				}
				all = append(all, pfx)
			}
		}
		if len(all) == found {
			return nil, fmt.Errorf("the OpenAI address list %s has no range", url)
		}
	}
	body, err := fetch(ctx, client, anthropic)
	if err != nil {
		return nil, err
	}
	page := string(body)
	start := strings.Index(page, outboundHeading)
	end := strings.Index(page, phasedOutHeading)
	if start < 0 || end < start {
		return nil, fmt.Errorf("the Anthropic address page %s has no outbound section followed by the phased-out one, so its layout changed", anthropic)
	}
	found := len(all)
	for _, m := range codeElement.FindAllStringSubmatch(page[start:end], -1) {
		for _, s := range strings.Fields(m[1]) {
			pfx, err := parseRange(s)
			if err != nil {
				logger.Warn("the outbound section of the Anthropic address page holds a value that is neither an address nor a range, so it is not left out",
					"page", anthropic, "value", s, "err", err)
				continue
			}
			all = append(all, pfx)
		}
	}
	if len(all) == found {
		return nil, fmt.Errorf("the outbound section of the Anthropic address page %s lists no range", anthropic)
	}
	return all, nil
}

func parseRange(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%s is an IPv4-mapped IPv6 range, which never matches the IPv4 addresses it maps; write it as an IPv4 range", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func fetch(ctx context.Context, client *http.Client, url string) (_ []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build the request for %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close %s: %w", url, cerr))
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRangeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) > maxRangeBytes {
		return nil, fmt.Errorf("read %s: larger than %d bytes", url, maxRangeBytes)
	}
	return body, nil
}
