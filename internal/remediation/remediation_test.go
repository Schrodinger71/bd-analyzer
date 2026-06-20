package remediation

import (
	"strings"
	"testing"
	"time"

	"bd-scan/internal/model"
)

func TestBuildAuthLifecycleIncludesAutoAndManualActions(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:             "AUTH-002",
				Title:          "Жизненный цикл аутентификации",
				Status:         model.StatusFail,
				Severity:       model.SeverityHigh,
				Recommendation: "Подтвердите параметры password_change_on_first_login и auth_storage_protected.",
			},
		},
	}

	proposals := Build(result, model.ConfigSnapshot{})
	if len(proposals) != 3 {
		t.Fatalf("expected 3 proposals, got %d", len(proposals))
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	if len(auto) != 2 {
		t.Fatalf("expected 2 auto-applicable proposals, got %d", len(auto))
	}

	autoKeys := map[string]bool{}
	for _, proposal := range auto {
		autoKeys[proposal.Key] = true
	}
	if !autoKeys["auth-password-encryption"] {
		t.Fatalf("expected auth-password-encryption among auto proposals, got %#v", auto)
	}
	if !autoKeys["auth-session-timeout"] {
		t.Fatalf("expected auth-session-timeout among auto proposals, got %#v", auto)
	}
}

func TestBuildAccessRoleModelIncludesSafeAutoSchemaHardening(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:             "ACCESS-002",
				Title:          "Ролевая модель администрирования",
				Status:         model.StatusFail,
				Severity:       model.SeverityHigh,
				Recommendation: "Сократить число SUPERUSER-ролей.",
			},
		},
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	if len(auto) != 1 {
		t.Fatalf("expected 1 auto-applicable proposal, got %d", len(auto))
	}
	if auto[0].Key != "access-public-schema-hardening" {
		t.Fatalf("unexpected auto proposal key: %s", auto[0].Key)
	}
	if len(auto[0].SQL) != 1 || auto[0].SQL[0] != "REVOKE CREATE ON SCHEMA public FROM PUBLIC" {
		t.Fatalf("unexpected SQL for access-public-schema-hardening: %#v", auto[0].SQL)
	}
}

func TestAuthSessionTimeoutCoversLockAndKeepaliveHardening(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:       "AUTH-002",
				Title:    "Жизненный цикл аутентификации",
				Status:   model.StatusFail,
				Severity: model.SeverityHigh,
			},
		},
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	var sessionProposal *Proposal
	for i := range auto {
		if auto[i].Key == "auth-session-timeout" {
			sessionProposal = &auto[i]
		}
	}
	if sessionProposal == nil {
		t.Fatalf("expected auth-session-timeout among auto proposals, got %#v", auto)
	}

	wantStatements := []string{
		"ALTER SYSTEM SET idle_in_transaction_session_timeout = '15min'",
		"ALTER SYSTEM SET lock_timeout = '30s'",
		"ALTER SYSTEM SET tcp_keepalives_idle = '300'",
		"ALTER SYSTEM SET tcp_keepalives_interval = '30'",
		"ALTER SYSTEM SET tcp_keepalives_count = '3'",
	}
	if len(sessionProposal.SQL) != len(wantStatements) {
		t.Fatalf("expected %d SQL statements, got %#v", len(wantStatements), sessionProposal.SQL)
	}
	for i, want := range wantStatements {
		if sessionProposal.SQL[i] != want {
			t.Fatalf("statement %d: expected %q, got %q", i, want, sessionProposal.SQL[i])
		}
	}

	// statement_timeout is deliberately NOT auto-applied: a blanket cap can kill
	// legitimate long-running jobs (pg_dump, index builds), unlike lock_timeout
	// or keepalives which only act on genuinely stuck/dead sessions.
	for _, statement := range sessionProposal.SQL {
		if strings.Contains(statement, "statement_timeout") {
			t.Fatalf("statement_timeout must not be auto-applied, got %q", statement)
		}
	}
}

func TestBuildAccessRoleModelAddsDatabaseRevokeWhenLiveConnectionKnown(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:       "ACCESS-002",
				Title:    "Ролевая модель администрирования",
				Status:   model.StatusFail,
				Severity: model.SeverityHigh,
			},
		},
	}

	snapshot := model.ConfigSnapshot{
		Connection: &model.ConnectionInfo{Host: "localhost", Port: 5432, Database: "appdb", User: "admin"},
	}

	auto := AutoApplicable(result, snapshot)
	if len(auto) != 1 || auto[0].Key != "access-public-schema-hardening" {
		t.Fatalf("expected access-public-schema-hardening auto proposal, got %#v", auto)
	}
	if len(auto[0].SQL) != 2 {
		t.Fatalf("expected 2 SQL statements when live database is known, got %#v", auto[0].SQL)
	}
	if auto[0].SQL[1] != `REVOKE CREATE ON DATABASE "appdb" FROM PUBLIC` {
		t.Fatalf("unexpected database-level revoke statement: %q", auto[0].SQL[1])
	}
}

func TestBuildAccessMatrixIncludesSafeDefaultPrivilegeHardening(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:             "ACCESS-003",
				Title:          "Матрицы доступа к объектам и процедурам",
				Status:         model.StatusFail,
				Severity:       model.SeverityHigh,
				Recommendation: "Запретить blanket-доступ для PUBLIC.",
			},
		},
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	if len(auto) != 1 {
		t.Fatalf("expected 1 auto-applicable proposal, got %d", len(auto))
	}
	if auto[0].Key != "access-default-privileges-hardening" {
		t.Fatalf("unexpected auto proposal key: %s", auto[0].Key)
	}
	if len(auto[0].SQL) != 3 {
		t.Fatalf("expected 3 SQL statements, got %#v", auto[0].SQL)
	}
}

func TestAuditSafeLoggingCoversDDLEvents(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:       "AUD-002",
				Title:    "Полнота состава и реквизитов журнала событий",
				Status:   model.StatusFail,
				Severity: model.SeverityHigh,
			},
		},
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	if len(auto) != 1 || auto[0].Key != "audit-safe-logging" {
		t.Fatalf("expected audit-safe-logging auto proposal, got %#v", auto)
	}

	found := false
	for _, statement := range auto[0].SQL {
		if statement == "ALTER SYSTEM SET log_statement = 'ddl'" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected log_statement = 'ddl' in audit-safe-logging SQL, got %#v", auto[0].SQL)
	}
}

func TestBuildAddsFSTECControlReferences(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "demo",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Findings: []model.Finding{
			{
				ID:             "AUD-001",
				Title:          "Механизмы регистрации событий безопасности",
				Status:         model.StatusWarn,
				Severity:       model.SeverityCritical,
				Recommendation: "Подтвердите audit subsystem и security_event_alerting.",
			},
		},
	}

	proposals := Build(result, model.ConfigSnapshot{})
	if len(proposals) == 0 {
		t.Fatal("expected at least one proposal")
	}

	foundControlRef := false
	for _, ref := range proposals[0].ControlRefs {
		if ref == "Приказ ФСТЭК №64, п.10.1" {
			foundControlRef = true
			break
		}
	}
	if !foundControlRef {
		t.Fatalf("expected FSTEC control reference in proposal, got %#v", proposals[0].ControlRefs)
	}
}
