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
	if len(proposals) != 2 {
		t.Fatalf("expected 2 proposals, got %d", len(proposals))
	}

	auto := AutoApplicable(result, model.ConfigSnapshot{})
	if len(auto) != 1 {
		t.Fatalf("expected 1 auto-applicable proposal, got %d", len(auto))
	}
	if auto[0].Key != "auth-password-encryption" {
		t.Fatalf("unexpected auto proposal key: %s", auto[0].Key)
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
