package normalize

import (
	"testing"

	"bd-scan/internal/model"
)

func TestBuildMarksAllAddressAsOpenRule(t *testing.T) {
	normalized := Build(model.ConfigSnapshot{
		Parameters: map[string]model.ConfigParameter{},
		HBARules: []model.HBARule{
			{Address: "all", Method: "scram-sha-256"},
			{Address: "10.10.0.0/16", Method: "scram-sha-256"},
		},
	})

	if len(normalized.OpenHBARules) != 1 {
		t.Fatalf("expected 1 open HBA rule, got %d", len(normalized.OpenHBARules))
	}
}
