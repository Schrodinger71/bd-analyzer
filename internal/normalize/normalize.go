package normalize

import (
	"strconv"
	"strings"

	"bd-scan/internal/model"
)

func Build(snapshot model.ConfigSnapshot) model.NormalizedConfig {
	parameters := make(map[string]string, len(snapshot.Parameters)+32)
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

		if address == "0.0.0.0/0" || address == "::/0" || address == "all" {
			normalized.OpenHBARules = append(normalized.OpenHBARules, rule)
		}
	}

	enrichDerivedParameters(&normalized)
	return normalized
}

func enrichDerivedParameters(normalized *model.NormalizedConfig) {
	setDefaultBool(normalized, "access_dac_enabled", true)
	setDefaultBool(normalized, "access_rbac_enabled", true)
	setDefaultBool(normalized, "procedure_acl_supported", true)
	setDefaultBool(normalized, "object_acl_supported", true)

	deriveRoleModel(normalized)
	deriveAuthSignals(normalized)
	deriveAuditSignals(normalized)
}

func deriveRoleModel(normalized *model.NormalizedConfig) {
	hasDBMSAdmin := false
	hasDBAdmin := false
	hasDBUser := false

	for _, role := range normalized.Snapshot.Roles {
		if role.Superuser {
			hasDBMSAdmin = true
		}
		if role.CreateDB || role.CreateRole || looksLikeDBAdminRole(role.Name) {
			hasDBAdmin = true
		}
		if role.Login && !role.Superuser {
			hasDBUser = true
		}
	}

	if hasDBMSAdmin {
		setDefaultBool(normalized, "role_dbms_admin_present", true)
		setDefaultBool(normalized, "dbms_admin_rights_complete", true)
	}
	if hasDBAdmin {
		setDefaultBool(normalized, "role_db_admin_present", true)
		setDefaultBool(normalized, "db_admin_rights_complete", true)
	}
	if hasDBUser {
		setDefaultBool(normalized, "role_db_user_present", true)
		setDefaultBool(normalized, "db_user_rights_complete", true)
	}
}

func deriveAuthSignals(normalized *model.NormalizedConfig) {
	if normalized.Param("password_encryption") == "scram-sha-256" {
		setDefaultBool(normalized, "auth_storage_protected", true)
	}
}

func deriveAuditSignals(normalized *model.NormalizedConfig) {
	logConnections, okConn := normalized.BoolParam("log_connections")
	logDisconnections, okDisconn := normalized.BoolParam("log_disconnections")
	logMinError := normalized.Param("log_min_error_statement")
	logDestination := normalized.Param("log_destination")
	logLinePrefix := normalized.Param("log_line_prefix")
	logStatement := normalized.Param("log_statement")
	logErrorVerbosity := normalized.Param("log_error_verbosity")
	logFileMode := normalized.Param("log_file_mode")

	minimumAuditSet := okConn && logConnections &&
		okDisconn && logDisconnections &&
		isErrorLevelOrStricter(logMinError)

	if minimumAuditSet {
		setDefaultBool(normalized, "security_events_minimum_set", true)
	}

	if normalized.HasPgAudit || normalized.Snapshot.Audit.Enabled || minimumAuditSet {
		setDefaultBool(normalized, "security_audit_enabled", true)
	}

	structuredLogging := containsAny(logDestination, "csvlog", "jsonlog") ||
		hasAllTokens(logLinePrefix, "%m", "%p", "%u", "%d")
	if structuredLogging {
		setDefaultBool(normalized, "security_log_structured", true)
	}

	if structuredLogging || containsAny(logLinePrefix, "%m", "%t", "%n") {
		setDefaultBool(normalized, "security_log_has_timestamp", true)
	}

	if structuredLogging || containsAny(logLinePrefix, "%c", "%l", "%p") {
		setDefaultBool(normalized, "security_log_has_event_id", true)
	}

	if normalized.HasPgAudit || normalized.Snapshot.Audit.Enabled || minimumAuditSet || (logStatement != "" && logStatement != "none") {
		setDefaultBool(normalized, "security_log_has_event_type", true)
	}

	if normalized.HasPgAudit || normalized.Snapshot.Audit.Enabled || (minimumAuditSet && logErrorVerbosity != "terse") {
		setDefaultBool(normalized, "security_event_importance", true)
	}

	if normalized.Snapshot.Audit.LogDirectoryProtected || isRestrictedLogMode(logFileMode) {
		setDefaultBool(normalized, "security_log_read_restricted", true)
	}

	if normalized.Snapshot.Audit.ImmutableStorage || hasLogRotation(normalized) {
		setDefaultBool(normalized, "security_log_archive_on_full", true)
	}
}

func setDefaultBool(normalized *model.NormalizedConfig, key string, value bool) {
	if _, exists := normalized.Parameters[key]; exists {
		return
	}
	if value {
		normalized.Parameters[key] = "true"
		return
	}
	normalized.Parameters[key] = "false"
}

func looksLikeDBAdminRole(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(name, "admin") || strings.Contains(name, "dba")
}

func containsAny(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if strings.Contains(value, strings.ToLower(token)) {
			return true
		}
	}
	return false
}

func hasAllTokens(value string, tokens ...string) bool {
	value = strings.ToLower(value)
	for _, token := range tokens {
		if !strings.Contains(value, strings.ToLower(token)) {
			return false
		}
	}
	return true
}

func isErrorLevelOrStricter(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "panic", "fatal", "error":
		return true
	default:
		return false
	}
}

func isRestrictedLogMode(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	parsed, err := strconv.ParseInt(value, 8, 32)
	if err != nil {
		parsed, err = strconv.ParseInt(value, 10, 32)
		if err != nil {
			return false
		}
	}

	return parsed <= 0o640
}

func hasLogRotation(normalized *model.NormalizedConfig) bool {
	return isPositiveNumericSetting(normalized.Param("log_rotation_size")) ||
		isPositiveNumericSetting(normalized.Param("log_rotation_age"))
}

func isPositiveNumericSetting(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return false
	}

	for i, r := range value {
		if r >= '0' && r <= '9' {
			continue
		}
		if i == 0 {
			return false
		}
		number, err := strconv.Atoi(value[:i])
		return err == nil && number > 0
	}

	number, err := strconv.Atoi(value)
	return err == nil && number > 0
}

func normalizeValue(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	return strings.ToLower(value)
}
