package model

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProtectionClass int

const (
	Class1 ProtectionClass = 1
	Class2 ProtectionClass = 2
	Class3 ProtectionClass = 3
	Class4 ProtectionClass = 4
	Class5 ProtectionClass = 5
	Class6 ProtectionClass = 6
)

type ControlProfile struct {
	Class                    ProtectionClass `json:"class"`
	RequiredTrustLevel       int             `json:"required_trust_level"`
	MinPasswordLength        int             `json:"min_password_length"`
	MinPasswordAlphabet      int             `json:"min_password_alphabet"`
	MaxFailedAuthAttempts    int             `json:"max_failed_auth_attempts"`
	RequireDAC               bool            `json:"require_dac"`
	RequireRBAC              bool            `json:"require_rbac"`
	RequireAudit             bool            `json:"require_audit"`
	RequireBackup            bool            `json:"require_backup"`
	RequireIntegrityRuntime  bool            `json:"require_integrity_runtime"`
	RequireAuditImportance   bool            `json:"require_audit_importance"`
	RequireConfigBackup      bool            `json:"require_config_backup"`
	RequireCluster           bool            `json:"require_cluster"`
	RequireObjectMemoryWipe  bool            `json:"require_object_memory_wipe"`
	RequireAllowlist         bool            `json:"require_allowlist"`
	RequireCodeRestrictions  bool            `json:"require_code_restrictions"`
	RequireIntegrityBlocking bool            `json:"require_integrity_blocking"`
}

func ParseProtectionClass(raw string) (ProtectionClass, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "class")
	raw = strings.TrimPrefix(raw, "класс")
	raw = strings.TrimSpace(raw)

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("не удалось определить класс защиты из %q", raw)
	}

	class := ProtectionClass(value)
	switch class {
	case Class1, Class2, Class3, Class4, Class5, Class6:
		return class, nil
	default:
		return 0, fmt.Errorf("неподдерживаемый класс защиты: %d", value)
	}
}

func AvailableProtectionClasses() []ProtectionClass {
	return []ProtectionClass{Class6, Class5, Class4, Class3, Class2, Class1}
}

func (c ProtectionClass) String() string {
	return fmt.Sprintf("%d класс", c)
}

func (c ProtectionClass) Label() string {
	switch c {
	case Class1:
		return "1 класс (максимальный профиль контроля)"
	case Class2:
		return "2 класс"
	case Class3:
		return "3 класс"
	case Class4:
		return "4 класс"
	case Class5:
		return "5 класс"
	case Class6:
		return "6 класс (базовый профиль контроля)"
	default:
		return "неизвестный класс"
	}
}

func (c ProtectionClass) Profile() ControlProfile {
	switch c {
	case Class1:
		return ControlProfile{Class: c, RequiredTrustLevel: 4, MinPasswordLength: 8, MinPasswordAlphabet: 70, MaxFailedAuthAttempts: 4, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireIntegrityRuntime: true, RequireAuditImportance: true, RequireConfigBackup: true, RequireCluster: true, RequireObjectMemoryWipe: true, RequireAllowlist: true, RequireCodeRestrictions: true, RequireIntegrityBlocking: true}
	case Class2:
		return ControlProfile{Class: c, RequiredTrustLevel: 4, MinPasswordLength: 8, MinPasswordAlphabet: 70, MaxFailedAuthAttempts: 4, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireIntegrityRuntime: true, RequireAuditImportance: true, RequireConfigBackup: true, RequireCluster: true, RequireObjectMemoryWipe: true, RequireAllowlist: true, RequireCodeRestrictions: true, RequireIntegrityBlocking: true}
	case Class3:
		return ControlProfile{Class: c, RequiredTrustLevel: 4, MinPasswordLength: 8, MinPasswordAlphabet: 70, MaxFailedAuthAttempts: 4, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireIntegrityRuntime: true, RequireAuditImportance: true, RequireConfigBackup: true, RequireCluster: true, RequireObjectMemoryWipe: true, RequireAllowlist: true, RequireCodeRestrictions: true, RequireIntegrityBlocking: true}
	case Class4:
		return ControlProfile{Class: c, RequiredTrustLevel: 4, MinPasswordLength: 8, MinPasswordAlphabet: 70, MaxFailedAuthAttempts: 4, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireIntegrityRuntime: true, RequireAuditImportance: true, RequireConfigBackup: true, RequireCluster: true, RequireObjectMemoryWipe: true, RequireAllowlist: true, RequireCodeRestrictions: true, RequireIntegrityBlocking: true}
	case Class5:
		return ControlProfile{Class: c, RequiredTrustLevel: 5, MinPasswordLength: 6, MinPasswordAlphabet: 70, MaxFailedAuthAttempts: 8, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireAllowlist: true, RequireIntegrityBlocking: true}
	default:
		return ControlProfile{Class: Class6, RequiredTrustLevel: 6, MinPasswordLength: 6, MinPasswordAlphabet: 60, MaxFailedAuthAttempts: 10, RequireDAC: true, RequireRBAC: true, RequireAudit: true, RequireBackup: true, RequireAllowlist: true, RequireIntegrityBlocking: true}
	}
}

type SourcePaths struct {
	PostgreSQLConf string `json:"postgresql_conf,omitempty"`
	HBAConf        string `json:"hba_conf,omitempty"`
	IdentConf      string `json:"ident_conf,omitempty"`
	MetadataJSON   string `json:"metadata_json,omitempty"`
}

type ConnectionInfo struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	SSLMode  string `json:"ssl_mode,omitempty"`
}

type ConfigParameter struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type HBARule struct {
	Type       string   `json:"type"`
	Database   string   `json:"database"`
	User       string   `json:"user"`
	Address    string   `json:"address,omitempty"`
	Method     string   `json:"method"`
	Options    []string `json:"options,omitempty"`
	SourceLine int      `json:"source_line"`
	Raw        string   `json:"raw"`
}

type IdentMap struct {
	MapName      string `json:"map_name"`
	SystemUser   string `json:"system_user"`
	DatabaseUser string `json:"database_user"`
	SourceLine   int    `json:"source_line"`
}

type Role struct {
	Name         string   `json:"name"`
	Login        bool     `json:"login"`
	Superuser    bool     `json:"superuser"`
	Replication  bool     `json:"replication"`
	BypassRLS    bool     `json:"bypass_rls"`
	Inherit      bool     `json:"inherit"`
	MemberOf     []string `json:"member_of,omitempty"`
	Privileges   []string `json:"privileges,omitempty"`
	Passwordless bool     `json:"passwordless"`
	Comment      string   `json:"comment,omitempty"`
}

type AuditSettings struct {
	Enabled               bool     `json:"enabled"`
	Provider              string   `json:"provider,omitempty"`
	Events                []string `json:"events,omitempty"`
	LogDirectoryProtected bool     `json:"log_directory_protected"`
	ImmutableStorage      bool     `json:"immutable_storage"`
}

type BackupSettings struct {
	Enabled       bool   `json:"enabled"`
	Schedule      string `json:"schedule,omitempty"`
	RetentionDays int    `json:"retention_days"`
	Encrypted     bool   `json:"encrypted"`
	TestedRestore bool   `json:"tested_restore"`
}

type IntegritySettings struct {
	ConfigControlEnabled bool `json:"config_control_enabled"`
	ChecksumsEnabled     bool `json:"checksums_enabled"`
}

type Metadata struct {
	Roles     []Role            `json:"roles"`
	Audit     AuditSettings     `json:"audit"`
	Backup    BackupSettings    `json:"backup"`
	Integrity IntegritySettings `json:"integrity"`
	Settings  map[string]string `json:"settings"`
	Notes     []string          `json:"notes"`
}

type ConfigSnapshot struct {
	Target             string                     `json:"target"`
	Connection         *ConnectionInfo            `json:"connection,omitempty"`
	Sources            SourcePaths                `json:"sources"`
	Parameters         map[string]ConfigParameter `json:"parameters"`
	HBARules           []HBARule                  `json:"hba_rules"`
	IdentMaps          []IdentMap                 `json:"ident_maps"`
	Roles              []Role                     `json:"roles"`
	Audit              AuditSettings              `json:"audit"`
	Backup             BackupSettings             `json:"backup"`
	Integrity          IntegritySettings          `json:"integrity"`
	Notes              []string                   `json:"notes"`
	CollectionWarnings []string                   `json:"collection_warnings"`
}

type NormalizedConfig struct {
	Snapshot     ConfigSnapshot    `json:"snapshot"`
	Parameters   map[string]string `json:"parameters"`
	WeakHBARules []HBARule         `json:"weak_hba_rules"`
	OpenHBARules []HBARule         `json:"open_hba_rules"`
	HasPgAudit   bool              `json:"has_pgaudit"`
}

func (n NormalizedConfig) Param(name string) string {
	return n.Parameters[strings.ToLower(strings.TrimSpace(name))]
}

func (n NormalizedConfig) BoolParam(name string) (bool, bool) {
	value := strings.ToLower(strings.TrimSpace(n.Param(name)))
	switch value {
	case "on", "true", "yes", "1":
		return true, true
	case "off", "false", "no", "0":
		return false, true
	default:
		return false, false
	}
}

func (n NormalizedConfig) IntParam(name string) (int, bool) {
	value := strings.TrimSpace(n.Param(name))
	if value == "" {
		return 0, false
	}

	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}

	return number, true
}

type FindingStatus string

const (
	StatusPass FindingStatus = "pass"
	StatusWarn FindingStatus = "warn"
	StatusFail FindingStatus = "fail"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 15
	case SeverityMedium:
		return 10
	default:
		return 5
	}
}

type Finding struct {
	ID             string        `json:"id"`
	Title          string        `json:"title"`
	Category       string        `json:"category"`
	Status         FindingStatus `json:"status"`
	Severity       Severity      `json:"severity"`
	Requirement    string        `json:"requirement"`
	Risk           string        `json:"risk"`
	Recommendation string        `json:"recommendation"`
	Evidence       []string      `json:"evidence"`
}

type Summary struct {
	Passed   int `json:"passed"`
	Warnings int `json:"warnings"`
	Failed   int `json:"failed"`
}

type AnalysisResult struct {
	Target      string          `json:"target"`
	Class       ProtectionClass `json:"class"`
	Profile     ControlProfile  `json:"profile"`
	GeneratedAt time.Time       `json:"generated_at"`
	Summary     Summary         `json:"summary"`
	Score       int             `json:"score"`
	Findings    []Finding       `json:"findings"`
	Notes       []string        `json:"notes,omitempty"`
}

func (r AnalysisResult) NonPassingFindings() []Finding {
	issues := make([]Finding, 0, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.Status != StatusPass {
			issues = append(issues, finding)
		}
	}

	sort.SliceStable(issues, func(i, j int) bool {
		return issues[i].Severity.Weight() > issues[j].Severity.Weight()
	})

	return issues
}
