package collector

import "testing"

func TestBuildPostgresDSNEncodesCredentials(t *testing.T) {
	req := Request{
		Host:     "db.example.local",
		User:     "audit user",
		Password: "p@ss word",
	}

	got := buildPostgresDSN(req, 5432, "prod db", "require")
	want := "postgres://audit%20user:p%40ss%20word@db.example.local:5432/prod%20db?application_name=bd-analyzer&connect_timeout=5&idle_in_transaction_session_timeout=10000&lock_timeout=3000&sslmode=require&statement_timeout=10000"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
