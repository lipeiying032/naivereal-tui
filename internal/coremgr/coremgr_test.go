package coremgr

import (
	"net/url"
	"testing"

	"naivereal/tui/internal/config"
)

func TestBuildCoreConfigEscapesCredentialsAndIPv6(t *testing.T) {
	p := &config.Profile{
		Server:              "2001:db8::1",
		Port:                8443,
		Username:            "user@example.com",
		Password:            "p:a%ss/word",
		InsecureConcurrency: 2,
	}
	got := BuildCoreConfig(p, "127.0.0.1:41080")
	u, err := url.Parse(got.Proxy)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != p.Server || u.Port() != "8443" {
		t.Fatalf("proxy host = %q, want [%s]:8443", u.Host, p.Server)
	}
	if u.User.Username() != p.Username {
		t.Fatalf("username = %q", u.User.Username())
	}
	password, ok := u.User.Password()
	if !ok || password != p.Password {
		t.Fatalf("password = %q, present=%v", password, ok)
	}
}

func TestBuildCoreConfigIncludesQuicTuning(t *testing.T) {
	enabled := false
	p := &config.Profile{
		Server:   "example.com",
		Port:     8443,
		Username: "u",
		Password: "p",
		QUIC: &config.QUICConfig{
			BBRProfile:                   "aggressive",
			EnableSocketRecvOptimization: &enabled,
		},
	}
	got := BuildCoreConfig(p, "127.0.0.1:41080")
	if got.Quic == nil || got.Quic.BBRProfile != "aggressive" || got.Quic.EnableSocketRecvOptimization == nil || *got.Quic.EnableSocketRecvOptimization {
		t.Fatalf("quic block = %+v", got.Quic)
	}
}
