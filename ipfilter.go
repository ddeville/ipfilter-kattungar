package ipfilter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	Rules map[string][]string `json:"rules,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Rules: make(map[string][]string),
	}
}

type IpFilter struct {
	next      http.Handler
	checkers  map[string]*Checker
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("rules cannot be empty")
	}

	checkers := make(map[string]*Checker)
	for hostname, ips := range(config.Rules) {
		checker, err := NewChecker(ips)
		if err != nil {
			return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", ips, err)
		}
		checkers[hostname] = checker
	}

	return &IpFilter {
		next,
		checkers,
	}, nil
}

func (a *IpFilter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ip = req.RemoteAddr
	}

	authorized := false
	for hostname, checker := range(a.checkers) {
		if req.Host == hostname || strings.HasSuffix(req.Host, "." + hostname) {
			if checker.IsAuthorized(ip) == nil {
				authorized = true
				break
			}
		}
	}

	if !authorized {
		statusCode := http.StatusForbidden
		rw.WriteHeader(statusCode)
		rw.Write([]byte(http.StatusText(statusCode)))
		return
	}

	a.next.ServeHTTP(rw, req)
}
