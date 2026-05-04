package service

import (
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestBuildUserEmail(t *testing.T) {
	cases := []struct {
		name string
		tag  string
		uid  int
		uuid string
		want string
	}{
		{"happy path", "anytls-in", 42, "11111111-2222-3333-4444-555555555555", "anytls-in|42|11111111-2222-3333-4444-555555555555"},
		{"zero uid yields empty", "anytls-in", 0, "u", ""},
		{"empty tag still allowed", "", 5, "x", "|5|x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildUserEmail(tc.tag, tc.uid, tc.uuid)
			if got != tc.want {
				t.Errorf("BuildUserEmail = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildUsers(t *testing.T) {
	users := []api.UserInfo{
		{Id: 1, Uuid: "uuid-a"},
		{Id: 0, Uuid: "skipped-zero-uid"},
		{Id: 2, Uuid: ""},
		{Id: 3, Uuid: "uuid-c"},
	}
	out := BuildUsers("tag", users)
	if len(out) != 2 {
		t.Fatalf("BuildUsers len = %d, want 2", len(out))
	}
	if out[0].Name != "tag|1|uuid-a" || out[0].Password != "uuid-a" {
		t.Errorf("entry 0 = %+v", out[0])
	}
	if out[1].Name != "tag|3|uuid-c" || out[1].Password != "uuid-c" {
		t.Errorf("entry 1 = %+v", out[1])
	}
}

func TestParseUIDFromEmail(t *testing.T) {
	cases := []struct {
		email   string
		want    int
		wantErr bool
	}{
		{"anytls-in|42|abc", 42, false},
		{"tag|1|short-uuid", 1, false},
		{"", 0, true},
		{"only|two", 0, true},
		{"tag|notanumber|uuid", 0, true},
		{"tag|0|uuid", 0, true},
		{"tag|-5|uuid", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.email, func(t *testing.T) {
			got, err := ParseUIDFromEmail(tc.email)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got uid=%d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("uid = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBuildUserEmailRoundTrip(t *testing.T) {
	const tag = "anytls-in"
	for uid := 1; uid <= 100; uid++ {
		email := BuildUserEmail(tag, uid, "u")
		got, err := ParseUIDFromEmail(email)
		if err != nil || got != uid {
			t.Errorf("roundtrip uid=%d -> email=%q parsed=%d err=%v",
				uid, email, got, err)
		}
	}
}
