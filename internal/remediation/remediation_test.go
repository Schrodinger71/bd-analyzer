package remediation

import (
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
