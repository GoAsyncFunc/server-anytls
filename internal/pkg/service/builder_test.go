package service

import (
	"os"
	"path/filepath"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestEqualStringSlice(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{nil, []string{}, true},
		{[]string{"x"}, []string{"x"}, true},
		{[]string{"x"}, []string{"y"}, false},
		{[]string{"x"}, []string{"x", "y"}, false},
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, false},
	}
	for _, tc := range cases {
		if got := equalStringSlice(tc.a, tc.b); got != tc.want {
			t.Errorf("equalStringSlice(%v,%v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBytesEqual(t *testing.T) {
	cases := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte("abc"), []byte("abc"), true},
		{[]byte("abc"), []byte("abd"), false},
		{[]byte("ab"), []byte("abc"), false},
	}
	for _, tc := range cases {
		if got := bytesEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("bytesEqual(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRoutesHash(t *testing.T) {
	if got := routesHash(nil); got != "" {
		t.Errorf("nil routes hash = %q, want empty", got)
	}
	if got := routesHash([]api.Route{}); got != "" {
		t.Errorf("empty routes hash = %q, want empty", got)
	}
	a := routesHash([]api.Route{{Action: "block", Match: "x.com"}})
	b := routesHash([]api.Route{{Action: "block", Match: "x.com"}})
	if a == "" || a != b {
		t.Errorf("hash should be stable; got %q vs %q", a, b)
	}
	c := routesHash([]api.Route{{Action: "block", Match: "y.com"}})
	if a == c {
		t.Errorf("different routes produced identical hash")
	}
}

func TestReadCertFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, []byte("cert-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	cBuf, kBuf := readCertFiles(certPath, keyPath)
	if string(cBuf) != "cert-data" || string(kBuf) != "key-data" {
		t.Errorf("readCertFiles wrong content: cert=%q key=%q", cBuf, kBuf)
	}

	cBuf, kBuf = readCertFiles("", "")
	if cBuf != nil || kBuf != nil {
		t.Errorf("empty paths should yield nils, got cert=%v key=%v", cBuf, kBuf)
	}

	cBuf, kBuf = readCertFiles(filepath.Join(dir, "missing"), filepath.Join(dir, "missing"))
	if cBuf != nil || kBuf != nil {
		t.Errorf("missing paths should yield nils, got cert=%v key=%v", cBuf, kBuf)
	}
}

func TestTrimPaddingScheme(t *testing.T) {
	if got := trimPaddingScheme(nil); got != nil {
		t.Errorf("nil scheme = %q, want nil", got)
	}
	if got := trimPaddingScheme([]string{}); got != nil {
		t.Errorf("empty scheme = %q, want nil", got)
	}
	got := trimPaddingScheme([]string{"stop=8", "0=30-30"})
	if string(got) != "stop=8\n0=30-30" {
		t.Errorf("scheme join = %q, want %q", got, "stop=8\n0=30-30")
	}
}

func TestFormatListenAddr(t *testing.T) {
	cases := []struct {
		port int
		want string
	}{
		{443, ":443"},
		{0, ":0"},
		{65535, ":65535"},
	}
	for _, tc := range cases {
		if got := formatListenAddr(tc.port); got != tc.want {
			t.Errorf("formatListenAddr(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestNodeChanged(t *testing.T) {
	mkNode := func(port int, sni string, scheme []string, routes []api.Route) *api.NodeInfo {
		return &api.NodeInfo{
			Routes: routes,
			AnyTls: &api.AnyTlsNode{
				CommonNode:    api.CommonNode{ServerPort: port, ServerName: sni},
				PaddingScheme: scheme,
			},
		}
	}
	cases := []struct {
		name string
		cur  *api.NodeInfo
		next *api.NodeInfo
		want bool
	}{
		{"nil cur", nil, mkNode(443, "a", nil, nil), true},
		{"port changed", mkNode(443, "a", nil, nil), mkNode(444, "a", nil, nil), true},
		{"sni changed", mkNode(443, "a", nil, nil), mkNode(443, "b", nil, nil), true},
		{"padding changed", mkNode(443, "a", []string{"x"}, nil), mkNode(443, "a", []string{"y"}, nil), true},
		{"routes changed", mkNode(443, "a", nil, nil), mkNode(443, "a", nil, []api.Route{{Action: "block", Match: "x"}}), true},
		{"nothing changed", mkNode(443, "a", []string{"x"}, nil), mkNode(443, "a", []string{"x"}, nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Builder{
				config:   &Config{},
				nodeInfo: tc.cur,
			}
			if got := b.nodeChanged(tc.next); got != tc.want {
				t.Errorf("nodeChanged = %v, want %v", got, tc.want)
			}
		})
	}
}
