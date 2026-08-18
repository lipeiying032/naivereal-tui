package sharelink

import (
	"net/url"
	"strings"
	"testing"
)

const testPub = "kWJW4VtHG8oCyj9tS6k6gJmW2lX0eZzQv8xP7bYy1Kc" // not a real key pair; structure only

func TestParseNaiveLink(t *testing.T) {
	p, err := Parse("naive+https://user:pass@example.com:8443?padding=1#MyNode")
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "example.com" || p.Port != 8443 || p.Username != "user" || p.Password != "pass" {
		t.Errorf("bad profile: %+v", p)
	}
	if p.Name != "MyNode" {
		t.Errorf("name = %q", p.Name)
	}
	if p.Reality != nil {
		t.Errorf("unexpected reality block: %+v", p.Reality)
	}
}

func TestIPv6AndEscapedCredentialsRoundtrip(t *testing.T) {
	link := "naivereal://user%40example.com:p%3Aa%25ss@[2001:db8::1]:8443?server_name=example.com&public_key=" + testPub + "&short_id=abcd#IPv6%20node"
	p, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "2001:db8::1" || p.Port != 8443 {
		t.Fatalf("server = %q:%d", p.Server, p.Port)
	}
	if p.Username != "user@example.com" || p.Password != "p:a%ss" {
		t.Fatalf("credentials = %q:%q", p.Username, p.Password)
	}
	built, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(built)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != p.Server || u.Port() != "8443" {
		t.Fatalf("roundtrip host = %q", u.Host)
	}
}

func TestRejectsInvalidPort(t *testing.T) {
	if _, err := Parse("naive+https://example.com:70000"); err == nil {
		t.Fatal("out-of-range port should fail")
	}
}

func TestParseNaiverealLink(t *testing.T) {
	link := "naivereal://u:p@203.0.113.10:443?server_name=www.microsoft.com&public_key=" + testPub + "&short_id=ab12cd34ef56&padding=1#main"
	p, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.Reality == nil || p.Reality.ServerName != "www.microsoft.com" || p.Reality.ShortID != "ab12cd34ef56" || p.Reality.PublicKey != testPub {
		t.Errorf("reality block wrong: %+v", p.Reality)
	}
	if p.Reality.Fingerprint != "chrome" {
		t.Errorf("fingerprint default = %q", p.Reality.Fingerprint)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse("vmess://x"); err == nil {
		t.Error("wrong scheme should fail")
	}
	if _, err := Parse("naivereal://u@host?server_name=&public_key=" + testPub + "&short_id=ab"); err == nil {
		t.Error("missing server_name should fail")
	}
	if _, err := Parse("naivereal://u@host?server_name=x.com&public_key=c2hvcnQ&short_id=ab"); err == nil {
		t.Error("short public_key should fail")
	}
	if _, err := Parse("naivereal://u@host?server_name=x.com&public_key=" + testPub + "&short_id=zz"); err == nil {
		t.Error("bad short_id should fail")
	}
}

func TestRoundtrip(t *testing.T) {
	p, err := Parse("naivereal://u:p@203.0.113.10?server_name=www.microsoft.com&public_key=" + testPub + "&short_id=abcd#main")
	if err != nil {
		t.Fatal(err)
	}
	link, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "naivereal://u:p@203.0.113.10?") {
		t.Errorf("reality build = %q", link)
	}
	p2, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Reality.PublicKey != testPub || p2.Reality.ShortID != "abcd" {
		t.Errorf("roundtrip mismatch: %+v", p2.Reality)
	}

	np, err := Parse("naive+https://u:p@example.com?padding=1#n")
	if err != nil {
		t.Fatal(err)
	}
	link2, err := Build(np)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link2, "naive+https://u:p@example.com") {
		t.Errorf("naive build = %q", link2)
	}
}

func TestParseAndBuildQuicTuning(t *testing.T) {
	link := "naive+https://u:p@example.com:8443?bbr_profile=aggressive&socket_recv_optimization=false#q"
	p, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.QUIC == nil || p.QUIC.BBRProfile != "aggressive" {
		t.Fatalf("QUIC BBR not parsed: %+v", p.QUIC)
	}
	if p.QUIC.EnableSocketRecvOptimization == nil || *p.QUIC.EnableSocketRecvOptimization {
		t.Fatalf("socket_recv_optimization not parsed: %+v", p.QUIC.EnableSocketRecvOptimization)
	}
	built, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(built)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("bbr_profile") != "aggressive" {
		t.Fatalf("built bbr_profile = %q", q.Get("bbr_profile"))
	}
	if q.Get("socket_recv_optimization") != "false" {
		t.Fatalf("built socket_recv_optimization = %q", q.Get("socket_recv_optimization"))
	}
	if u.Scheme != "quic" {
		t.Fatalf("built scheme = %q, want quic", u.Scheme)
	}
}

func TestParseAndBuildQuicLink(t *testing.T) {
	p, err := Parse("quic://u:p@example.com:8443?bbr_profile=aggressive#q")
	if err != nil {
		t.Fatal(err)
	}
	if p.QUIC == nil || p.QUIC.BBRProfile != "aggressive" {
		t.Fatalf("QUIC not parsed: %+v", p.QUIC)
	}
	if p.Reality != nil {
		t.Fatalf("unexpected reality: %+v", p.Reality)
	}
	built, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(built)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "quic" {
		t.Fatalf("built scheme = %q, want quic", u.Scheme)
	}
	if u.Query().Get("bbr_profile") != "aggressive" {
		t.Fatalf("built bbr_profile = %q", u.Query().Get("bbr_profile"))
	}
}

func TestParseAndBuildQuicRealityLink(t *testing.T) {
	link := "naivereal+quic://u:p@example.com:8443?server_name=www.microsoft.com&public_key=" + testPub + "&short_id=ab12cd34ef56&bbr_profile=aggressive#q"
	p, err := Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.QUIC == nil || p.QUIC.BBRProfile != "aggressive" {
		t.Fatalf("QUIC not parsed: %+v", p.QUIC)
	}
	if p.Reality == nil || p.Reality.ServerName != "www.microsoft.com" || p.Reality.PublicKey != testPub || p.Reality.ShortID != "ab12cd34ef56" {
		t.Fatalf("reality not parsed: %+v", p.Reality)
	}
	built, err := Build(p)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(built)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "naivereal+quic" {
		t.Fatalf("built scheme = %q, want naivereal+quic", u.Scheme)
	}
	if u.Query().Get("bbr_profile") != "aggressive" {
		t.Fatalf("built bbr_profile = %q", u.Query().Get("bbr_profile"))
	}
	if u.Query().Get("server_name") != "www.microsoft.com" {
		t.Fatalf("built server_name = %q", u.Query().Get("server_name"))
	}
}
