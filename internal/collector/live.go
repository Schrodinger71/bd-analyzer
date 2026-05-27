package collector

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"bd-scan/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func buildConnectionInfo(req Request) *model.ConnectionInfo {
	if !hasConnectionRequest(req) {
		return nil
	}

	port := req.Port
	if port == 0 {
		port = 5432
	}

	sslMode := strings.TrimSpace(req.SSLMode)
	if sslMode == "" {
		sslMode = "prefer"
	}

	return &model.ConnectionInfo{
		Host:     strings.TrimSpace(req.Host),
		Port:     port,
		Database: strings.TrimSpace(req.Database),
		User:     strings.TrimSpace(req.User),
		SSLMode:  sslMode,
	}
}

func hasConnectionRequest(req Request) bool {
	return strings.TrimSpace(req.Host) != "" || req.Port != 0 || strings.TrimSpace(req.User) != "" || strings.TrimSpace(req.Database) != ""
}

func maybeCollectLive(req Request) (model.ConfigSnapshot, bool, error) {
	if !hasConnectionRequest(req) {
		return model.ConfigSnapshot{}, false, nil
	}

	snapshot, err := collectFromDatabase(req)
	if err != nil {
		return model.ConfigSnapshot{}, false, err
	}

	return snapshot, true, nil
}

func collectFromDatabase(req Request) (model.ConfigSnapshot, error) {
	port := req.Port
	if port == 0 {
		port = 5432
	}

	databaseName := strings.TrimSpace(req.Database)
	if databaseName == "" {
		databaseName = "postgres"
	}

	sslMode := strings.TrimSpace(req.SSLMode)
	if sslMode == "" {
		sslMode = "prefer"
	}

	dsn := fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		strings.TrimSpace(req.Host),
		port,
		databaseName,
		strings.TrimSpace(req.User),
		req.Password,
		sslMode,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return model.ConfigSnapshot{}, fmt.Errorf("не удалось открыть соединение с PostgreSQL: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return model.ConfigSnapshot{}, fmt.Errorf("не удалось подключиться к PostgreSQL: %w", err)
	}

	snapshot := model.ConfigSnapshot{
		Target: databaseName,
		Connection: &model.ConnectionInfo{
			Host:     strings.TrimSpace(req.Host),
			Port:     port,
			Database: databaseName,
			User:     strings.TrimSpace(req.User),
			SSLMode:  sslMode,
		},
		Parameters: make(map[string]model.ConfigParameter),
	}

	if err := collectSettings(ctx, db, &snapshot); err != nil {
		return snapshot, err
	}
	collectRoles(ctx, db, &snapshot)
	collectHBARules(ctx, db, &snapshot)
	collectIdentMaps(ctx, db, &snapshot)
	inferAuditSettings(&snapshot)

	return snapshot, nil
}

func collectSettings(ctx context.Context, db *sql.DB, snapshot *model.ConfigSnapshot) error {
	rows, err := db.QueryContext(ctx, `
		select
			name,
			setting,
			coalesce(sourcefile, '')
		from pg_settings
	`)
	if err != nil {
		return fmt.Errorf("не удалось получить параметры из pg_settings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var value string
		var source string
		if err := rows.Scan(&name, &value, &source); err != nil {
			return fmt.Errorf("ошибка чтения строки pg_settings: %w", err)
		}

		normalizedName := strings.ToLower(strings.TrimSpace(name))
		snapshot.Parameters[normalizedName] = model.ConfigParameter{
			Name:   normalizedName,
			Value:  strings.TrimSpace(value),
			Source: source,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("ошибка чтения результатов pg_settings: %w", err)
	}

	if param, ok := snapshot.Parameters["config_file"]; ok {
		snapshot.Sources.PostgreSQLConf = strings.TrimSpace(param.Value)
	}
	if param, ok := snapshot.Parameters["hba_file"]; ok {
		snapshot.Sources.HBAConf = strings.TrimSpace(param.Value)
	}
	if param, ok := snapshot.Parameters["ident_file"]; ok {
		snapshot.Sources.IdentConf = strings.TrimSpace(param.Value)
	}

	return nil
}

func collectRoles(ctx context.Context, db *sql.DB, snapshot *model.ConfigSnapshot) {
	rows, err := db.QueryContext(ctx, `
		select
			r.rolname,
			r.rolcanlogin,
			r.rolsuper,
			r.rolreplication,
			r.rolbypassrls,
			r.rolinherit,
			coalesce(string_agg(m.rolname, ',' order by m.rolname), '')
		from pg_roles r
		left join pg_auth_members am on am.member = r.oid
		left join pg_roles m on m.oid = am.roleid
		group by r.rolname, r.rolcanlogin, r.rolsuper, r.rolreplication, r.rolbypassrls, r.rolinherit
		order by r.rolname
	`)
	if err != nil {
		snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось получить роли из pg_roles: %v", err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var role model.Role
		var memberships string
		if err := rows.Scan(&role.Name, &role.Login, &role.Superuser, &role.Replication, &role.BypassRLS, &role.Inherit, &memberships); err != nil {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("ошибка чтения роли из pg_roles: %v", err))
			return
		}
		if memberships != "" {
			role.MemberOf = strings.Split(memberships, ",")
		}
		snapshot.Roles = append(snapshot.Roles, role)
	}
}

func collectHBARules(ctx context.Context, db *sql.DB, snapshot *model.ConfigSnapshot) {
	rows, err := db.QueryContext(ctx, `
		select
			line_number,
			type,
			coalesce(array_to_string(database, ','), ''),
			coalesce(array_to_string(user_name, ','), ''),
			coalesce(address, ''),
			coalesce(auth_method, ''),
			coalesce(array_to_string(options, ','), ''),
			coalesce(error, '')
		from pg_hba_file_rules
		order by line_number
	`)
	if err != nil {
		snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось получить правила pg_hba_file_rules: %v", err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rule model.HBARule
		var options string
		var parseErr string
		if err := rows.Scan(&rule.SourceLine, &rule.Type, &rule.Database, &rule.User, &rule.Address, &rule.Method, &options, &parseErr); err != nil {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("ошибка чтения pg_hba_file_rules: %v", err))
			return
		}

		rule.Type = strings.ToLower(rule.Type)
		rule.Method = strings.ToLower(rule.Method)
		rule.Raw = fmt.Sprintf("%s %s %s %s %s", rule.Type, rule.Database, rule.User, rule.Address, rule.Method)
		if options != "" {
			rule.Options = strings.Split(options, ",")
		}
		if parseErr != "" {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("строка HBA %d: %s", rule.SourceLine, parseErr))
		}
		snapshot.HBARules = append(snapshot.HBARules, rule)
	}
}

func collectIdentMaps(ctx context.Context, db *sql.DB, snapshot *model.ConfigSnapshot) {
	rows, err := db.QueryContext(ctx, `
		select
			line_number,
			coalesce(map_name, ''),
			coalesce(sys_name, ''),
			coalesce(pg_username, ''),
			coalesce(error, '')
		from pg_ident_file_mappings
		order by line_number
	`)
	if err != nil {
		snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось получить правила pg_ident_file_mappings: %v", err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var mapping model.IdentMap
		var parseErr string
		if err := rows.Scan(&mapping.SourceLine, &mapping.MapName, &mapping.SystemUser, &mapping.DatabaseUser, &parseErr); err != nil {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("ошибка чтения pg_ident_file_mappings: %v", err))
			return
		}
		if parseErr != "" {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("строка ident %d: %s", mapping.SourceLine, parseErr))
		}
		snapshot.IdentMaps = append(snapshot.IdentMaps, mapping)
	}
}

func inferAuditSettings(snapshot *model.ConfigSnapshot) {
	sharedLibraries := strings.ToLower(snapshot.Parameters["shared_preload_libraries"].Value)
	pgAuditEnabled := strings.Contains(sharedLibraries, "pgaudit")
	pgAuditLog := strings.TrimSpace(snapshot.Parameters["pgaudit.log"].Value)

	snapshot.Audit.Enabled = pgAuditEnabled
	if pgAuditEnabled {
		snapshot.Audit.Provider = "pgaudit"
	}
	if pgAuditLog != "" {
		snapshot.Audit.Events = strings.Split(pgAuditLog, ",")
	}
}

func mergeLiveSnapshot(snapshot *model.ConfigSnapshot, live model.ConfigSnapshot) {
	if snapshot.Connection == nil {
		snapshot.Connection = live.Connection
	}

	if snapshot.Sources.PostgreSQLConf == "" {
		snapshot.Sources.PostgreSQLConf = live.Sources.PostgreSQLConf
	}
	if snapshot.Sources.HBAConf == "" {
		snapshot.Sources.HBAConf = live.Sources.HBAConf
	}
	if snapshot.Sources.IdentConf == "" {
		snapshot.Sources.IdentConf = live.Sources.IdentConf
	}

	for key, value := range live.Parameters {
		snapshot.Parameters[key] = value
	}

	if len(snapshot.HBARules) == 0 && len(live.HBARules) > 0 {
		snapshot.HBARules = live.HBARules
	}
	if len(snapshot.IdentMaps) == 0 && len(live.IdentMaps) > 0 {
		snapshot.IdentMaps = live.IdentMaps
	}
	if len(live.Roles) > 0 {
		snapshot.Roles = live.Roles
	}

	if live.Audit.Enabled || live.Audit.Provider != "" || len(live.Audit.Events) > 0 {
		snapshot.Audit = live.Audit
	}

	snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, live.CollectionWarnings...)
}
