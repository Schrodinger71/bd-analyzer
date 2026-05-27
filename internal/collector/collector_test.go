package collector

import "testing"

func TestBuildLocalSourceReadPlanUsesOnlyExplicitPaths(t *testing.T) {
	req := Request{
		Host:           "db.example.local",
		Port:           5432,
		Database:       "postgres",
		User:           "postgres",
		PostgreSQLConf: "  C:\\pg\\postgresql.conf  ",
		HBAConf:        "  ",
		IdentConf:      "\t",
	}

	plan := buildLocalSourceReadPlan(req)

	if plan.postgresqlConf != "C:\\pg\\postgresql.conf" {
		t.Fatalf("unexpected postgresql.conf path: %q", plan.postgresqlConf)
	}
	if plan.hbaConf != "" {
		t.Fatalf("expected empty hba path, got %q", plan.hbaConf)
	}
	if plan.identConf != "" {
		t.Fatalf("expected empty ident path, got %q", plan.identConf)
	}
}

func TestBuildLocalSourceReadPlanSkipsLiveOnlyConnectionFields(t *testing.T) {
	req := Request{
		Host:     "db.example.local",
		Port:     5432,
		Database: "postgres",
		User:     "postgres",
		Password: "secret",
		SSLMode:  "require",
	}

	plan := buildLocalSourceReadPlan(req)

	if plan.postgresqlConf != "" || plan.hbaConf != "" || plan.identConf != "" {
		t.Fatalf("expected no local files to read for live-only request, got %+v", plan)
	}
}
