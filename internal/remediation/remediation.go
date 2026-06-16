package remediation

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"bd-scan/internal/collector"
	"bd-scan/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Proposal struct {
	Key          string
	Title        string
	Priority     string
	ApplyMode    string
	Target       string
	Rationale    string
	Steps        []string
	Snippet      string
	FindingID    string
	FindingName  string
	AutoApply    bool
	SQL          []string
	ReloadConfig bool
}

type AppliedChange struct {
	Title              string
	Statement          string
	Applied            bool
	Message            string
	FindingID          string
	FindingKey         string
	VerificationQuery  string
	VerificationResult string
	VerificationError  string
}

type ApplyResult struct {
	Changes []AppliedChange
}

type ProgressUpdate struct {
	Phase   string
	Current int
	Total   int
	Message string
}

type ProgressFunc func(ProgressUpdate)

func (r ApplyResult) HasFailures() bool {
	for _, change := range r.Changes {
		if !change.Applied {
			return true
		}
	}
	return false
}

func (r ApplyResult) Summary() string {
	if len(r.Changes) == 0 {
		return "Безопасных автоизменений для применения не найдено."
	}

	var applied int
	for _, change := range r.Changes {
		if change.Applied {
			applied++
		}
	}
	return fmt.Sprintf("Автоприменение завершено: успешно %d, с ошибками %d.", applied, len(r.Changes)-applied)
}

func Build(result model.AnalysisResult, snapshot model.ConfigSnapshot) []Proposal {
	unique := make(map[string]Proposal)
	order := make([]string, 0, len(result.Findings))

	for _, finding := range result.NonPassingFindings() {
		for _, proposal := range buildProposal(finding, result, snapshot) {
			if proposal.Key == "" {
				proposal.Key = proposal.Title
			}
			if _, exists := unique[proposal.Key]; exists {
				continue
			}
			unique[proposal.Key] = proposal
			order = append(order, proposal.Key)
		}
	}

	proposals := make([]Proposal, 0, len(order))
	for _, key := range order {
		proposals = append(proposals, unique[key])
	}

	sort.SliceStable(proposals, func(i, j int) bool {
		return priorityWeight(proposals[i].Priority) > priorityWeight(proposals[j].Priority)
	})
	return proposals
}

func AutoApplicable(result model.AnalysisResult, snapshot model.ConfigSnapshot) []Proposal {
	proposals := Build(result, snapshot)
	filtered := make([]Proposal, 0, len(proposals))
	for _, proposal := range proposals {
		if proposal.AutoApply && len(proposal.SQL) > 0 {
			filtered = append(filtered, proposal)
		}
	}
	return filtered
}

func RenderText(result model.AnalysisResult, snapshot model.ConfigSnapshot) string {
	proposals := Build(result, snapshot)
	var builder strings.Builder

	builder.WriteString("ПЛАН УСИЛЕНИЯ И ПРИВЕДЕНИЯ К ТРЕБОВАНИЯМ ФСТЭК\n")
	builder.WriteString("============================================\n")
	builder.WriteString(fmt.Sprintf("Цель анализа: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("Профиль контроля: %s\n", result.Class.Label()))
	builder.WriteString(fmt.Sprintf("Найдено рекомендаций: %d\n", len(proposals)))
	if snapshot.Connection != nil {
		builder.WriteString(fmt.Sprintf("Live-БД: %s:%d/%s\n", snapshot.Connection.Host, snapshot.Connection.Port, snapshot.Connection.Database))
	}

	auto := AutoApplicable(result, snapshot)
	builder.WriteString(fmt.Sprintf("Безопасных автоизменений: %d\n", len(auto)))
	builder.WriteString("\n")

	if len(proposals) == 0 {
		builder.WriteString("Критичных доработок не выявлено. Поддерживайте текущее состояние и подтверждайте организационные меры отдельно.\n")
		return builder.String()
	}

	for index, proposal := range proposals {
		builder.WriteString(fmt.Sprintf("%d. %s\n", index+1, proposal.Title))
		builder.WriteString(fmt.Sprintf("   Приоритет: %s\n", proposal.Priority))
		builder.WriteString(fmt.Sprintf("   Способ: %s\n", proposal.ApplyMode))
		if proposal.AutoApply {
			builder.WriteString("   Автоприменение: поддерживается\n")
		} else {
			builder.WriteString("   Автоприменение: только вручную\n")
		}
		if proposal.Target != "" {
			builder.WriteString(fmt.Sprintf("   Цель изменения: %s\n", proposal.Target))
		}
		builder.WriteString(fmt.Sprintf("   Основание: %s (%s)\n", proposal.FindingName, proposal.FindingID))
		builder.WriteString(fmt.Sprintf("   Почему: %s\n", proposal.Rationale))
		if len(proposal.Steps) > 0 {
			builder.WriteString("   Шаги:\n")
			for _, step := range proposal.Steps {
				builder.WriteString("   - " + step + "\n")
			}
		}
		if proposal.Snippet != "" {
			builder.WriteString("   Шаблон изменения:\n")
			for _, line := range strings.Split(strings.TrimSpace(proposal.Snippet), "\n") {
				builder.WriteString("     " + line + "\n")
			}
		}
		builder.WriteString("\n")
	}

	builder.WriteString("Примечание: автоприменение ограничено безопасными и обратимыми изменениями. Опасные действия по ролям, pg_hba, TLS и архитектуре кластера подтверждаются вручную.\n")
	return builder.String()
}

func RenderAutoApplySummary(result model.AnalysisResult, snapshot model.ConfigSnapshot) string {
	proposals := AutoApplicable(result, snapshot)
	if len(proposals) == 0 {
		return "Безопасные автоизменения не найдены. Для текущих несоответствий требуются ручные действия администратора."
	}

	var builder strings.Builder
	builder.WriteString("Будут применены только безопасные изменения к живой PostgreSQL:\n")
	for _, proposal := range proposals {
		builder.WriteString("- " + proposal.Title + "\n")
		for _, statement := range proposal.SQL {
			builder.WriteString("  " + statement + "\n")
		}
		if proposal.ReloadConfig {
			builder.WriteString("  SELECT pg_reload_conf();\n")
		}
	}
	builder.WriteString("\nРекомендуется выполнить резервное копирование конфигурации перед применением.")
	return builder.String()
}

func ApplySafe(req collector.Request, result model.AnalysisResult, snapshot model.ConfigSnapshot) (ApplyResult, error) {
	if !req.UsesLiveConnection() {
		return ApplyResult{}, fmt.Errorf("автоприменение доступно только для живой PostgreSQL")
	}

	proposals := AutoApplicable(result, snapshot)
	if len(proposals) == 0 {
		return ApplyResult{}, nil
	}

	db, err := sql.Open("pgx", buildDSN(req))
	if err != nil {
		return ApplyResult{}, fmt.Errorf("не удалось открыть соединение для автоприменения: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return ApplyResult{}, fmt.Errorf("не удалось подключиться к PostgreSQL для автоприменения: %w", err)
	}

	var out ApplyResult
	reloadNeeded := false
	for _, proposal := range proposals {
		for _, statement := range proposal.SQL {
			change := AppliedChange{
				Title:      proposal.Title,
				Statement:  statement,
				FindingID:  proposal.FindingID,
				FindingKey: proposal.Key,
			}

			stmtCtx, stmtCancel := context.WithTimeout(ctx, 6*time.Second)
			_, execErr := db.ExecContext(stmtCtx, statement)
			stmtCancel()
			if execErr != nil {
				change.Message = execErr.Error()
				out.Changes = append(out.Changes, change)
				continue
			}

			change.Applied = true
			change.Message = "изменение применено"
			out.Changes = append(out.Changes, change)
		}
		if proposal.ReloadConfig {
			reloadNeeded = true
		}
	}

	if reloadNeeded {
		change := AppliedChange{
			Title:      "Перезагрузка конфигурации PostgreSQL",
			Statement:  "SELECT pg_reload_conf()",
			FindingKey: "reload-config",
		}
		reloadCtx, reloadCancel := context.WithTimeout(ctx, 6*time.Second)
		_, reloadErr := db.ExecContext(reloadCtx, "SELECT pg_reload_conf()")
		reloadCancel()
		if reloadErr != nil {
			change.Message = reloadErr.Error()
		} else {
			change.Applied = true
			change.Message = "конфигурация перечитана"
		}
		out.Changes = append(out.Changes, change)
	}

	return out, nil
}

func ApplySafeWithProgress(req collector.Request, result model.AnalysisResult, snapshot model.ConfigSnapshot, progress ProgressFunc) (ApplyResult, error) {
	if progress == nil {
		return ApplySafe(req, result, snapshot)
	}
	if !req.UsesLiveConnection() {
		return ApplyResult{}, fmt.Errorf("автоприменение доступно только для живой PostgreSQL")
	}

	proposals := AutoApplicable(result, snapshot)
	if len(proposals) == 0 {
		return ApplyResult{}, nil
	}

	totalSteps := countApplySteps(proposals)
	currentStep := 0
	emitProgress := func(phase, message string) {
		progress(ProgressUpdate{
			Phase:   phase,
			Current: currentStep,
			Total:   totalSteps,
			Message: message,
		})
	}

	currentStep++
	emitProgress("connect", "Подключение к live PostgreSQL для автоусиления.")

	db, err := sql.Open("pgx", buildDSN(req))
	if err != nil {
		return ApplyResult{}, fmt.Errorf("не удалось открыть соединение для автоприменения: %w", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return ApplyResult{}, fmt.Errorf("не удалось подключиться к PostgreSQL для автоприменения: %w", err)
	}

	var out ApplyResult
	reloadNeeded := false
	for _, proposal := range proposals {
		for _, statement := range proposal.SQL {
			currentStep++
			emitProgress("apply", fmt.Sprintf("Применение: %s", proposal.Title))

			change := AppliedChange{
				Title:      proposal.Title,
				Statement:  statement,
				FindingID:  proposal.FindingID,
				FindingKey: proposal.Key,
			}

			stmtCtx, stmtCancel := context.WithTimeout(ctx, 6*time.Second)
			_, execErr := db.ExecContext(stmtCtx, statement)
			stmtCancel()
			if execErr != nil {
				change.Message = execErr.Error()
				out.Changes = append(out.Changes, change)
				continue
			}

			change.Applied = true
			change.Message = "изменение применено"
			out.Changes = append(out.Changes, change)
		}
		if proposal.ReloadConfig {
			reloadNeeded = true
		}
	}

	if reloadNeeded {
		currentStep++
		emitProgress("reload", "Перечитка конфигурации PostgreSQL.")

		change := AppliedChange{
			Title:      "Перезагрузка конфигурации PostgreSQL",
			Statement:  "SELECT pg_reload_conf()",
			FindingKey: "reload-config",
		}
		reloadCtx, reloadCancel := context.WithTimeout(ctx, 6*time.Second)
		_, reloadErr := db.ExecContext(reloadCtx, "SELECT pg_reload_conf()")
		reloadCancel()
		if reloadErr != nil {
			change.Message = reloadErr.Error()
		} else {
			change.Applied = true
			change.Message = "конфигурация перечитана"
		}
		out.Changes = append(out.Changes, change)
	}

	for i := range out.Changes {
		query := verificationQueryForStatement(out.Changes[i].Statement)
		if !out.Changes[i].Applied || query == "" {
			continue
		}

		currentStep++
		emitProgress("verify", fmt.Sprintf("Проверка: %s", out.Changes[i].Title))

		out.Changes[i].VerificationQuery = query
		verifyCtx, verifyCancel := context.WithTimeout(ctx, 6*time.Second)
		value, verifyErr := readSingleValue(verifyCtx, db, query)
		verifyCancel()
		if verifyErr != nil {
			out.Changes[i].VerificationError = verifyErr.Error()
			continue
		}
		out.Changes[i].VerificationResult = value
	}

	emitProgress("done", "Автоусиление и первичная проверка завершены.")
	return out, nil
}

func buildProposal(finding model.Finding, result model.AnalysisResult, snapshot model.ConfigSnapshot) []Proposal {
	base := Proposal{
		Priority:    severityLabel(finding.Severity),
		Rationale:   finding.Recommendation,
		FindingID:   finding.ID,
		FindingName: finding.Title,
	}

	switch finding.ID {
	case "AUTH-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:          "auth-password-encryption",
			Title:        "Усилить политику хранения паролей",
			ApplyMode:    "Live SQL + парольная ротация",
			Target:       "PostgreSQL cluster",
			AutoApply:    true,
			ReloadConfig: true,
			SQL: []string{
				"ALTER SYSTEM SET password_encryption = 'scram-sha-256'",
			},
			Steps: []string{
				"Включить SCRAM для новых паролей.",
				"После автоприменения вручную перезадать пароли критичных учетных записей.",
				"Задокументировать требования по длине и алфавиту паролей в metadata/регламенте.",
			},
			Snippet: "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\nSELECT pg_reload_conf();\n-- Далее вручную выполнить ALTER ROLE <role> WITH PASSWORD '<new-strong-password>';",
		})}
	case "AUTH-002":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "auth-lifecycle-org",
			Title:     "Закрыть пробелы жизненного цикла аутентификации",
			ApplyMode: "Оргмеры + внешняя интеграция",
			Target:    "Политика доступа и PAM/SSO",
			Steps: []string{
				"Ввести смену первичного пароля при выдаче доступа.",
				"Настроить блокировку после серии неуспешных входов через внешний контур аутентификации.",
				"Подтвердить masking/lockout/unlock в эксплуатационной документации.",
			},
		})}
	case "ACCESS-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "access-hba-manual",
			Title:     "Сузить правила клиентского доступа и исключить небезопасные методы",
			ApplyMode: "pg_hba.conf",
			Target:    firstNonEmpty(snapshot.Sources.HBAConf, "pg_hba.conf"),
			Steps: []string{
				"Убрать trust/password для сетевых подключений.",
				"Ограничить подсети конкретными адресами или сегментами администраторов и приложений.",
				"Перевести сетевые правила на hostssl + scram-sha-256.",
			},
			Snippet: "hostssl all all 127.0.0.1/32 scram-sha-256\nhostssl all all ::1/128 scram-sha-256\n# заменить широкие и trust-правила на адресно ограниченные",
		})}
	case "ACCESS-002":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "access-role-model",
			Title:     "Пересобрать ролевую модель и сократить избыточные полномочия",
			ApplyMode: "Live SQL + ревизия ролей",
			Target:    "Роли и привилегии PostgreSQL",
			Steps: []string{
				"Выделить отдельные роли администратора СУБД, администратора БД и прикладного пользователя.",
				"Сократить число SUPERUSER-ролей до минимально необходимого набора.",
				"Проверить права роли public и избыточные атрибуты REPLICATION/BYPASSRLS.",
			},
			Snippet: "REVOKE CREATE ON SCHEMA public FROM PUBLIC;\nREVOKE ALL ON DATABASE <db_name> FROM PUBLIC;\nALTER ROLE <role> NOSUPERUSER NOBYPASSRLS NOREPLICATION;",
		})}
	case "ACCESS-003":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "access-acl-model",
			Title:     "Формализовать матрицы доступа к объектам и процедурам",
			ApplyMode: "Live SQL + модель прав",
			Target:    "ACL объектов и процедур",
			Steps: []string{
				"Определить ролевую матрицу GRANT/REVOKE по схемам, таблицам и функциям.",
				"Запретить blanket-доступ для PUBLIC.",
				"Закрепить минимально необходимые ACL в migration-скриптах.",
			},
			Snippet: "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;\nGRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <app_role>;\nGRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO <app_role>;",
		})}
	case "AUD-001", "AUD-002":
		return []Proposal{mergeProposal(base, Proposal{
			Key:          "audit-safe-logging",
			Title:        "Усилить журналирование событий безопасности",
			ApplyMode:    "ALTER SYSTEM + pg_reload_conf()",
			Target:       firstNonEmpty(snapshot.Sources.PostgreSQLConf, "postgresql.conf"),
			AutoApply:    true,
			ReloadConfig: true,
			SQL: []string{
				"ALTER SYSTEM SET log_connections = 'on'",
				"ALTER SYSTEM SET log_disconnections = 'on'",
				"ALTER SYSTEM SET log_min_error_statement = 'error'",
				"ALTER SYSTEM SET log_line_prefix = '%m [%p] db=%d,user=%u,app=%a,client=%h '",
				"ALTER SYSTEM SET log_error_verbosity = 'verbose'",
				"ALTER SYSTEM SET log_file_mode = '0600'",
				"ALTER SYSTEM SET log_rotation_age = '1d'",
				"ALTER SYSTEM SET log_rotation_size = '100MB'",
			},
			Steps: []string{
				"Безопасно включить логирование подключений, отключений и ошибок.",
				"Отдельно оценить возможность включения pgAudit, если расширение установлено и рестарт допустим.",
				"Проверить защищённость каталога журналов и порядок архивации.",
			},
			Snippet: "ALTER SYSTEM SET log_connections = 'on';\nALTER SYSTEM SET log_disconnections = 'on';\nALTER SYSTEM SET log_min_error_statement = 'error';\nSELECT pg_reload_conf();\n-- Включение pgAudit оставить как отдельное подтвержденное изменение.",
		})}
	case "BACKUP-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "backup-process",
			Title:     "Закрыть требования по резервному копированию и восстановлению",
			ApplyMode: "Оргмеры + backup pipeline",
			Target:    "Контур резервного копирования",
			Steps: []string{
				"Настроить регулярный backup базы и конфигурации СУБД.",
				"Определить срок хранения и шифрование резервных копий.",
				"Провести и задокументировать тестовое восстановление.",
			},
			Snippet: "pg_dump -Fc -d <db_name> -f <backup_file>\n# или настроить base backup / WAL archive по принятой схеме",
		})}
	case "AVAIL-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "availability-architecture",
			Title:     "Подтвердить или внедрить отказоустойчивую схему для требуемого класса",
			ApplyMode: "Архитектурное изменение",
			Target:    "Кластер/репликация/обновление",
			Steps: []string{
				"Определить целевую HA-схему: primary-standby, Patroni, etcd/Consul или другой утверждённый контур.",
				"Задокументировать rolling update и rollback без простоя.",
				"Подтвердить синхронизацию конфигурации между узлами.",
			},
		})}
	case "MEM-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "memory-wipe-policy",
			Title:     "Закрыть требования по безопасному удалению данных и объектов",
			ApplyMode: "Оргмеры + защищённая утилизация",
			Target:    "Политика удаления данных",
			Steps: []string{
				"Определить процедуру безопасного удаления файлов БД, журналов и резервных копий.",
				"Подтвердить многократную перезапись или криптографическое уничтожение носителя.",
				"Отдельно описать удаление объектов БД для усиленных классов.",
			},
		})}
	case "ENV-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "environment-hardening",
			Title:     "Ограничить программную среду и загрузку недоверенного кода",
			ApplyMode: "Оргмеры + hardening ОС/расширений",
			Target:    "Host OS / extension policy",
			Steps: []string{
				"Утвердить allowlist для расширений и вспомогательного ПО.",
				"Ограничить установку сторонних библиотек и процедур пользователями БД.",
				"Контролировать целостность бинарных файлов и shared libraries.",
			},
		})}
	case "INT-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "integrity-controls",
			Title:     "Подтвердить контроль целостности конфигурации и данных",
			ApplyMode: "Оргмеры + конфигурация кластера",
			Target:    "Конфигурация PostgreSQL и файловая система",
			Steps: []string{
				"Внедрить контроль целостности конфигурационных файлов.",
				"Проверить возможность включения data checksums для новых инсталляций или при переинициализации кластера.",
				"Задокументировать процедуру контроля изменений конфигурации.",
			},
		})}
	default:
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "generic-" + finding.ID,
			Title:     "Устранить выявленное несоответствие: " + finding.Title,
			ApplyMode: "Ручная проработка",
			Target:    finding.Category,
			Steps: []string{
				"Сопоставить рекомендацию анализа с текущим регламентом.",
				"Подготовить изменение конфигурации, SQL или эксплуатационной процедуры.",
				"Повторно запустить анализ живой БД после внесения изменений.",
			},
		})}
	}
}

func mergeProposal(base Proposal, extra Proposal) Proposal {
	if extra.Priority == "" {
		extra.Priority = base.Priority
	}
	if extra.Rationale == "" {
		extra.Rationale = base.Rationale
	}
	if extra.FindingID == "" {
		extra.FindingID = base.FindingID
	}
	if extra.FindingName == "" {
		extra.FindingName = base.FindingName
	}
	return extra
}

func priorityWeight(priority string) int {
	switch strings.ToLower(priority) {
	case "критический":
		return 4
	case "высокий":
		return 3
	case "средний":
		return 2
	default:
		return 1
	}
}

func severityLabel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "Критический"
	case model.SeverityHigh:
		return "Высокий"
	case model.SeverityMedium:
		return "Средний"
	default:
		return "Низкий"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func buildDSN(req collector.Request) string {
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

	query := url.Values{}
	query.Set("connect_timeout", "5")
	query.Set("sslmode", sslMode)
	query.Set("statement_timeout", "10000")
	query.Set("lock_timeout", "3000")
	query.Set("application_name", "bd-analyzer-remediation")

	dsn := &url.URL{
		Scheme:   "postgres",
		Host:     net.JoinHostPort(strings.TrimSpace(req.Host), strconv.Itoa(port)),
		Path:     "/" + databaseName,
		RawQuery: query.Encode(),
	}

	user := strings.TrimSpace(req.User)
	switch {
	case user != "" && req.Password != "":
		dsn.User = url.UserPassword(user, req.Password)
	case user != "":
		dsn.User = url.User(user)
	}

	return dsn.String()
}

func countApplySteps(proposals []Proposal) int {
	total := 1
	reloadNeeded := false

	for _, proposal := range proposals {
		total += len(proposal.SQL)
		if proposal.ReloadConfig {
			reloadNeeded = true
		}
		for _, statement := range proposal.SQL {
			if verificationQueryForStatement(statement) != "" {
				total++
			}
		}
	}

	if reloadNeeded {
		total++
	}

	return total
}

func verificationQueryForStatement(statement string) string {
	trimmed := strings.TrimSpace(strings.TrimSuffix(statement, ";"))
	upper := strings.ToUpper(trimmed)
	const prefix = "ALTER SYSTEM SET "
	if !strings.HasPrefix(upper, prefix) {
		return ""
	}

	remainder := strings.TrimSpace(trimmed[len(prefix):])
	eqIndex := strings.Index(remainder, "=")
	if eqIndex <= 0 {
		return ""
	}

	parameter := strings.TrimSpace(remainder[:eqIndex])
	if parameter == "" {
		return ""
	}

	return "SHOW " + parameter
}

func readSingleValue(ctx context.Context, db *sql.DB, query string) (string, error) {
	var value string
	if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}
