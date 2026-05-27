package normalize

import (
	"strings"

	"bd-scan/internal/model"
)

func Build(snapshot model.ConfigSnapshot) model.NormalizedConfig {
	parameters := make(map[string]string, len(snapshot.Parameters))
	for key, param := range snapshot.Parameters {
		parameters[strings.ToLower(strings.TrimSpace(key))] = normalizeValue(param.Value)
	}

	normalized := model.NormalizedConfig{
		Snapshot:   snapshot,
		Parameters: parameters,
	}

	preloadLibraries := normalized.Param("shared_preload_libraries")
	normalized.HasPgAudit = snapshot.Audit.Enabled ||
		strings.EqualFold(snapshot.Audit.Provider, "pgaudit") ||
		strings.Contains(preloadLibraries, "pgaudit")

	for _, rule := range snapshot.HBARules {
		method := strings.ToLower(strings.TrimSpace(rule.Method))
		address := strings.TrimSpace(strings.ToLower(rule.Address))

		if method == "trust" || method == "password" || method == "md5" {
			normalized.WeakHBARules = append(normalized.WeakHBARules, rule)
		}

		if address == "0.0.0.0/0" || address == "::/0" {
			normalized.OpenHBARules = append(normalized.OpenHBARules, rule)
		}
	}

	return normalized
}

func normalizeValue(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	return strings.ToLower(value)
}
