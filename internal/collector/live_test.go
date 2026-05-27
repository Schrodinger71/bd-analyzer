package collector

import "testing"

func TestBuildPostgresDSNEncodesCredentials(t *testing.T) {
	req := Request{
		Host:     "db.example.local",
		User:     "audit user",
		Password: "p@ss word",
	}

	got := buildPostgresDSN(req, 5432, "prod db", "require")
	want := "postgres://audit%20user:p%40ss%20word@db.example.local:5432/prod%20db?connect_timeout=5&sslmode=require"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
