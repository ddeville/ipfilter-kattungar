package ipfilter_kattungar

import (
	"context"
	"errors"
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
	next     http.Handler
	checkers map[string]*Checker
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("rules cannot be empty")
	}

	checkers := make(map[string]*Checker)
	for hostname, ips := range config.Rules {
		checker, err := NewChecker(ips)
		if err != nil {
			return nil, fmt.Errorf("cannot parse CIDR whitelist %s: %w", ips, err)
		}
		checkers[hostname] = checker
	}

	return &IpFilter{
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
	for hostname, checker := range a.checkers {
		if req.Host == hostname || strings.HasSuffix(req.Host, "."+hostname) {
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

type Checker struct {
	authorizedIPs    []*net.IP
	authorizedIPsNet []*net.IPNet
}

func NewChecker(trustedIPs []string) (*Checker, error) {
	if len(trustedIPs) == 0 {
		return nil, errors.New("no trusted IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range trustedIPs {
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.authorizedIPs = append(checker.authorizedIPs, &ipAddr)
		} else {
			_, ipAddr, err := net.ParseCIDR(ipMask)
			if err != nil {
				return nil, fmt.Errorf("parsing CIDR trusted IPs %s: %w", ipAddr, err)
			}
			checker.authorizedIPsNet = append(checker.authorizedIPsNet, ipAddr)
		}
	}

	return checker, nil
}

func (ip *Checker) IsAuthorized(addr string) error {
	var invalidMatches []string

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ok, err := ip.Contains(host)
	if err != nil {
		return err
	}

	if !ok {
		invalidMatches = append(invalidMatches, addr)
		return fmt.Errorf("%q matched none of the trusted IPs", strings.Join(invalidMatches, ", "))
	}

	return nil
}

func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("empty IP address")
	}

	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		return false, fmt.Errorf("unable to parse address: %s", addr)
	}

	for _, authorizedIP := range ip.authorizedIPs {
		if authorizedIP.Equal(ipAddr) {
			return true, nil
		}
	}

	for _, authorizedNet := range ip.authorizedIPsNet {
		if authorizedNet.Contains(ipAddr) {
			return true, nil
		}
	}

	return false, nil
}
