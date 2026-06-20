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
	ControlRefs  []string
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

type Dashboard struct {
	TotalProposals     int
	AutoApplicable     int
	ManualActions      int
	CriticalFindings   int
	HighFindings       int
	WarningFindings    int
	FailedFindings     int
	QuickWins          []Proposal
	ManualTop          []Proposal
	CoveredControlRefs []string
}

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

func BuildDashboard(result model.AnalysisResult, snapshot model.ConfigSnapshot) Dashboard {
	proposals := Build(result, snapshot)
	autoApplicable := AutoApplicable(result, snapshot)

	dashboard := Dashboard{
		TotalProposals: len(proposals),
		AutoApplicable: len(autoApplicable),
		ManualActions:  len(proposals) - len(autoApplicable),
	}

	for _, finding := range result.Findings {
		switch finding.Status {
		case model.StatusWarn:
			dashboard.WarningFindings++
		case model.StatusFail:
			dashboard.FailedFindings++
		}

		if finding.Status == model.StatusPass {
			continue
		}
		switch finding.Severity {
		case model.SeverityCritical:
			dashboard.CriticalFindings++
		case model.SeverityHigh:
			dashboard.HighFindings++
		}
	}

	dashboard.QuickWins = append(dashboard.QuickWins, autoApplicable...)
	for _, proposal := range proposals {
		if proposal.AutoApply {
			continue
		}
		dashboard.ManualTop = append(dashboard.ManualTop, proposal)
	}
	if len(dashboard.QuickWins) > 4 {
		dashboard.QuickWins = dashboard.QuickWins[:4]
	}
	if len(dashboard.ManualTop) > 6 {
		dashboard.ManualTop = dashboard.ManualTop[:6]
	}
	dashboard.CoveredControlRefs = collectControlRefs(proposals)
	return dashboard
}

func RenderDashboardSummary(result model.AnalysisResult, snapshot model.ConfigSnapshot) string {
	dashboard := BuildDashboard(result, snapshot)
	var builder strings.Builder

	builder.WriteString("ПАНЕЛЬ УСИЛЕНИЯ И СООТВЕТСТВИЯ ФСТЭК\n")
	builder.WriteString("====================================\n")
	builder.WriteString(fmt.Sprintf("Профиль: %s\n", result.Class.Label()))
	builder.WriteString(fmt.Sprintf("Итоговый балл: %d/100\n", result.Score))
	builder.WriteString(fmt.Sprintf("Несоответствий: %d | Предупреждений: %d\n", dashboard.FailedFindings, dashboard.WarningFindings))
	builder.WriteString(fmt.Sprintf("Критичных зон: %d | Высоких зон: %d\n", dashboard.CriticalFindings, dashboard.HighFindings))
	builder.WriteString(fmt.Sprintf("Мер усиления: %d | Автоматических: %d | Ручных: %d\n", dashboard.TotalProposals, dashboard.AutoApplicable, dashboard.ManualActions))
	if snapshot.Connection != nil {
		builder.WriteString(fmt.Sprintf("Live PostgreSQL: %s:%d/%s (%s)\n", snapshot.Connection.Host, snapshot.Connection.Port, snapshot.Connection.Database, snapshot.Connection.User))
	}
	if len(dashboard.CoveredControlRefs) > 0 {
		builder.WriteString("Контрольные пункты ФСТЭК: " + strings.Join(dashboard.CoveredControlRefs, ", ") + "\n")
	}
	if len(dashboard.QuickWins) > 0 {
		builder.WriteString("\nБыстрые безопасные шаги:\n")
		for _, proposal := range dashboard.QuickWins {
			builder.WriteString("- " + proposal.Title + "\n")
		}
	}
	return builder.String()
}

func RenderManualPlan(result model.AnalysisResult, snapshot model.ConfigSnapshot) string {
	proposals := Build(result, snapshot)
	var builder strings.Builder

	builder.WriteString("РУЧНОЙ ПЛАН УСИЛЕНИЯ\n")
	builder.WriteString("===================\n")

	count := 0
	for _, proposal := range proposals {
		if proposal.AutoApply {
			continue
		}
		count++
		builder.WriteString(fmt.Sprintf("%d. %s\n", count, proposal.Title))
		builder.WriteString(fmt.Sprintf("   Приоритет: %s\n", proposal.Priority))
		builder.WriteString(fmt.Sprintf("   Способ: %s\n", proposal.ApplyMode))
		if proposal.Target != "" {
			builder.WriteString(fmt.Sprintf("   Цель: %s\n", proposal.Target))
		}
		if len(proposal.ControlRefs) > 0 {
			builder.WriteString(fmt.Sprintf("   ФСТЭК: %s\n", strings.Join(proposal.ControlRefs, ", ")))
		}
		for _, step := range proposal.Steps {
			builder.WriteString("   - " + step + "\n")
		}
		builder.WriteString("\n")
	}

	if count == 0 {
		builder.WriteString("Критичных ручных доработок не требуется.\n")
	}
	return builder.String()
}

func RenderControlCoverage(result model.AnalysisResult, snapshot model.ConfigSnapshot) string {
	proposals := Build(result, snapshot)
	if len(proposals) == 0 {
		return "Контрольные пункты ФСТЭК закрыты без дополнительных мер усиления."
	}

	var builder strings.Builder
	builder.WriteString("ПОКРЫТИЕ КОНТРОЛЬНЫХ ПУНКТОВ ФСТЭК\n")
	builder.WriteString("=================================\n")
	for _, proposal := range proposals {
		if len(proposal.ControlRefs) == 0 {
			continue
		}
		builder.WriteString("- " + strings.Join(proposal.ControlRefs, ", ") + ": " + proposal.Title + "\n")
	}
	return builder.String()
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
		if len(proposal.ControlRefs) > 0 {
			builder.WriteString(fmt.Sprintf("   ФСТЭК: %s\n", strings.Join(proposal.ControlRefs, ", ")))
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

	builder.WriteString("Примечание: автоприменение ограничено безопасными и обратимыми изменениями. Ролевая модель, кластер, регламенты и сертификационные подтверждения выполняются вручную.\n")
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
		if len(proposal.ControlRefs) > 0 {
			builder.WriteString("  ФСТЭК: " + strings.Join(proposal.ControlRefs, ", ") + "\n")
		}
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
		ControlRefs: controlRefsForFinding(finding.ID),
		Priority:    severityLabel(finding.Severity),
		Rationale:   finding.Recommendation,
		FindingID:   finding.ID,
		FindingName: finding.Title,
	}

	switch finding.ID {
	case "TRUST-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "trust-profile-evidence",
			Title:     "Подтвердить требуемый уровень доверия СУБД",
			ApplyMode: "Документация и metadata JSON",
			Target:    "Сертификационный профиль СУБД",
			Steps: []string{
				"Проверить сертификат и эксплуатационную документацию СУБД на соответствие требуемому уровню доверия.",
				"Зафиксировать параметр dbms_trust_level в metadata JSON и артефактах аудита.",
				"Привязать подтверждение к выбранному классу защиты и экземпляру БД.",
			},
			Snippet: "\"settings\": {\n  \"dbms_trust_level\": \"4\"\n}",
		})}
	case "OS-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "os-certification-evidence",
			Title:     "Подтвердить сертифицированную ОС и ее класс защиты",
			ApplyMode: "Документация, инвентаризация и metadata JSON",
			Target:    "Хостовая операционная система",
			Steps: []string{
				"Подтвердить, что PostgreSQL размещен в сертифицированной ОС допустимого класса защиты.",
				"Задать в metadata JSON параметры os_certified и os_protection_class.",
				"Синхронизировать сведения с паспортом ИС и контуром сопровождения.",
			},
			Snippet: "\"settings\": {\n  \"os_certified\": \"true\",\n  \"os_protection_class\": \"4\"\n}",
		})}
	case "AUTH-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "auth-password-policy",
			Title:     "Усилить парольную политику и лимит попыток входа",
			ApplyMode: "Metadata JSON + регламент доступа",
			Target:    "Политика аутентификации",
			Steps: []string{
				fmt.Sprintf("Установить password_min_length не ниже %d.", result.Profile.MinPasswordLength),
				fmt.Sprintf("Установить password_alphabet_size не ниже %d.", result.Profile.MinPasswordAlphabet),
				fmt.Sprintf("Ограничить auth_max_failed_attempts значением не выше %d.", result.Profile.MaxFailedAuthAttempts),
				"Зафиксировать требования в metadata JSON и в регламенте выдачи доступа.",
			},
			Snippet: fmt.Sprintf("\"settings\": {\n  \"password_min_length\": \"%d\",\n  \"password_alphabet_size\": \"%d\",\n  \"auth_max_failed_attempts\": \"%d\"\n}", result.Profile.MinPasswordLength, result.Profile.MinPasswordAlphabet, result.Profile.MaxFailedAuthAttempts),
		})}
	case "AUTH-002":
		return []Proposal{
			mergeProposal(base, Proposal{
				Key:          "auth-password-encryption",
				Title:        "Перевести хранение новых паролей на SCRAM",
				ApplyMode:    "ALTER SYSTEM + pg_reload_conf()",
				Target:       firstNonEmpty(snapshot.Sources.PostgreSQLConf, "postgresql.conf"),
				AutoApply:    true,
				ReloadConfig: true,
				SQL: []string{
					"ALTER SYSTEM SET password_encryption = 'scram-sha-256'",
				},
				Steps: []string{
					"Включить SCRAM для новых паролей и задокументировать это как часть защищенного хранения аутентификационной информации.",
					"После применения вручную перевыпустить пароли критичных учетных записей.",
				},
				Snippet: "ALTER SYSTEM SET password_encryption = 'scram-sha-256';\nSELECT pg_reload_conf();\nALTER ROLE <role> WITH PASSWORD '<new-strong-password>';",
			}),
			mergeProposal(base, Proposal{
				Key:          "auth-session-timeout",
				Title:        "Ограничить зависшие, простаивающие и неактивные сессии",
				ApplyMode:    "ALTER SYSTEM + pg_reload_conf()",
				Target:       firstNonEmpty(snapshot.Sources.PostgreSQLConf, "postgresql.conf"),
				AutoApply:    true,
				ReloadConfig: true,
				SQL: []string{
					"ALTER SYSTEM SET idle_in_transaction_session_timeout = '15min'",
					"ALTER SYSTEM SET lock_timeout = '30s'",
					"ALTER SYSTEM SET tcp_keepalives_idle = '300'",
					"ALTER SYSTEM SET tcp_keepalives_interval = '30'",
					"ALTER SYSTEM SET tcp_keepalives_count = '3'",
				},
				Steps: []string{
					"Автоматически закрывать сессии, простаивающие внутри незавершенной транзакции, чтобы снизить риск удержания заблокированной аутентифицированной сессии.",
					"Ограничить время ожидания блокировки достаточно щадящим порогом (30 секунд), чтобы не повлиять на штатную нагрузку, но прервать аномальное ожидание захваченной сессией.",
					"Включить TCP keepalive, чтобы сервер обнаруживал и закрывал разорванные «зависшие» соединения вместо бессрочного удержания слота сессии.",
				},
				Snippet: "ALTER SYSTEM SET idle_in_transaction_session_timeout = '15min';\nALTER SYSTEM SET lock_timeout = '30s';\nALTER SYSTEM SET tcp_keepalives_idle = '300';\nALTER SYSTEM SET tcp_keepalives_interval = '30';\nALTER SYSTEM SET tcp_keepalives_count = '3';\nSELECT pg_reload_conf();",
			}),
			mergeProposal(base, Proposal{
				Key:       "auth-lifecycle-org",
				Title:     "Закрыть пробелы жизненного цикла аутентификации",
				ApplyMode: "Оргмеры + внешняя интеграция",
				Target:    "Политика доступа и PAM/SSO",
				Steps: []string{
					"Ввести смену первичного пароля при выдаче доступа.",
					"Настроить блокировку после серии неуспешных входов через внешний контур аутентификации.",
					"Подтвердить masking, lockout и unlock в эксплуатационной документации и metadata JSON.",
				},
				Snippet: "\"settings\": {\n  \"password_change_on_first_login\": \"true\",\n  \"auth_lockout_enabled\": \"true\",\n  \"auth_unlock_supported\": \"true\",\n  \"password_input_masking\": \"true\"\n}",
			}),
		}
	case "ACCESS-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "access-dac-rbac-confirmation",
			Title:     "Подтвердить дискреционную и ролевую модель доступа",
			ApplyMode: "Metadata JSON + модель ролей",
			Target:    "Матрица управления доступом",
			Steps: []string{
				"Подтвердить применение DAC и RBAC в целевой инсталляции PostgreSQL.",
				"Зафиксировать access_dac_enabled и access_rbac_enabled в metadata JSON.",
				"Привязать модель ролей к ролям СУБД, администратора БД и прикладных пользователей.",
			},
			Snippet: "\"settings\": {\n  \"access_dac_enabled\": \"true\",\n  \"access_rbac_enabled\": \"true\"\n}",
		})}
	case "ACCESS-002":
		publicCreateSQL := []string{"REVOKE CREATE ON SCHEMA public FROM PUBLIC"}
		publicCreateSteps := []string{
			"Безопасно отозвать право на создание объектов в схеме public у роли PUBLIC, не затрагивая существующие подключения и права CONNECT.",
		}
		publicCreateSnippet := "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
		if snapshot.Connection != nil && strings.TrimSpace(snapshot.Connection.Database) != "" {
			dbStatement := fmt.Sprintf("REVOKE CREATE ON DATABASE %s FROM PUBLIC", quoteIdent(snapshot.Connection.Database))
			publicCreateSQL = append(publicCreateSQL, dbStatement)
			publicCreateSteps = append(publicCreateSteps, "Отозвать право создавать новые схемы в подключенной базе данных у роли PUBLIC, не затрагивая право подключения (CONNECT).")
			publicCreateSnippet += "\n" + dbStatement + ";"
		}
		publicCreateSteps = append(publicCreateSteps, "Выдать право CREATE точечно только тем ролям, которым оно действительно требуется.")

		return []Proposal{
			mergeProposal(base, Proposal{
				Key:          "access-public-schema-hardening",
				Title:        "Запретить роли PUBLIC создавать объекты и новые схемы",
				ApplyMode:    "Live SQL (REVOKE)",
				Target:       "Схема public и база данных",
				AutoApply:    true,
				ReloadConfig: false,
				SQL:          publicCreateSQL,
				Steps:        publicCreateSteps,
				Snippet:      publicCreateSnippet,
			}),
			mergeProposal(base, Proposal{
				Key:       "access-role-model",
				Title:     "Пересобрать ролевую модель и сократить избыточные полномочия",
				ApplyMode: "Live SQL + ревизия ролей",
				Target:    "Роли и привилегии PostgreSQL",
				Steps: []string{
					"Выделить отдельные роли администратора СУБД, администратора БД и прикладного пользователя.",
					"Сократить число SUPERUSER-ролей до минимально необходимого набора.",
					"Проверить права роли public и избыточные атрибуты REPLICATION и BYPASSRLS.",
				},
				Snippet: "REVOKE ALL ON DATABASE <db_name> FROM PUBLIC;\nALTER ROLE <role> NOSUPERUSER NOBYPASSRLS NOREPLICATION;",
			}),
		}
	case "ACCESS-003":
		return []Proposal{
			mergeProposal(base, Proposal{
				Key:          "access-default-privileges-hardening",
				Title:        "Закрыть blanket-доступ PUBLIC для новых объектов схемы public",
				ApplyMode:    "Live SQL (ALTER DEFAULT PRIVILEGES)",
				Target:       "Схема public",
				AutoApply:    true,
				ReloadConfig: false,
				SQL: []string{
					"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC",
					"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC",
					"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC",
				},
				Steps: []string{
					"Изменить права по умолчанию для будущих таблиц, функций и последовательностей схемы public, не затрагивая уже выданные права на существующие объекты.",
					"Выдавать доступ к новым объектам точечно через явные GRANT прикладным ролям.",
				},
				Snippet: "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;\nALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC;\nALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;",
			}),
			mergeProposal(base, Proposal{
				Key:       "access-acl-model",
				Title:     "Формализовать матрицы доступа к объектам и процедурам",
				ApplyMode: "Live SQL + модель прав",
				Target:    "ACL объектов и процедур",
				Steps: []string{
					"Определить ролевую матрицу GRANT и REVOKE по схемам, таблицам и функциям.",
					"Запретить blanket-доступ для PUBLIC на уже существующих объектах.",
					"Закрепить минимально необходимые ACL в migration-скриптах и эксплуатационной документации.",
				},
				Snippet: "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;\nGRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <app_role>;\nGRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO <app_role>;",
			}),
		}
	case "INT-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "integrity-controls",
			Title:     "Подтвердить контроль целостности конфигурации и блокировки",
			ApplyMode: "Оргмеры + контроль запуска",
			Target:    "Конфигурация PostgreSQL и файловая система",
			Steps: []string{
				"Внедрить контроль целостности конфигурационных файлов и процедур при запуске.",
				"Подтвердить уведомления администраторов и блокирование доступа пользователей при нарушении целостности.",
				"Задокументировать процедуру проверки и порядок реагирования.",
			},
			Snippet: "\"integrity\": {\n  \"config_control_enabled\": true,\n  \"checksums_enabled\": true\n},\n\"settings\": {\n  \"integrity_alert_dbms_admin\": \"true\",\n  \"integrity_alert_db_admin\": \"true\",\n  \"integrity_block_system_users\": \"true\",\n  \"integrity_block_db_users\": \"true\"\n}",
		})}
	case "INT-002":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "integrity-runtime-daily",
			Title:     "Организовать суточный контроль целостности в процессе работы",
			ApplyMode: "Регламент + планировщик задач",
			Target:    "Контур эксплуатационного контроля",
			Steps: []string{
				"Настроить ежедневную проверку целостности процедур и критичных компонентов БД.",
				"Сохранять результаты проверки в журнале сопровождения или SIEM.",
				"Зафиксировать параметр integrity_runtime_daily в metadata JSON.",
			},
			Snippet: "\"settings\": {\n  \"integrity_runtime_daily\": \"true\"\n}",
		})}
	case "AUD-001":
		return []Proposal{
			auditSafeLoggingProposal(base, snapshot),
			mergeProposal(base, Proposal{
				Key:       "audit-pgaudit-manual",
				Title:     "Подтвердить подсистему аудита и оповещения администраторов",
				ApplyMode: "pgAudit или внешний аудит + документация",
				Target:    "Подсистема регистрации событий",
				Steps: []string{
					"Подключить pgAudit или эквивалентный механизм регистрации событий безопасности.",
					"Подтвердить параметры security_event_alerting, security_log_structured, security_log_read_restricted и security_log_archive_on_full.",
					"Описать маршрутизацию уведомлений администраторам СУБД и БД.",
				},
				Snippet: "\"audit\": {\n  \"enabled\": true,\n  \"provider\": \"pgaudit\",\n  \"log_directory_protected\": true,\n  \"immutable_storage\": true\n}",
			}),
		}
	case "AUD-002":
		return []Proposal{
			auditSafeLoggingProposal(base, snapshot),
			mergeProposal(base, Proposal{
				Key:       "audit-coverage-metadata",
				Title:     "Подтвердить обязательный состав событий и реквизитов журнала",
				ApplyMode: "Metadata JSON + аудит-профиль",
				Target:    "Структура журнала безопасности",
				Steps: []string{
					"Подтвердить регистрацию минимального набора событий безопасности.",
					"Подтвердить наличие идентификатора события, времени, типа и важности события для 4 класса.",
					"Привязать профиль журнала к SIEM или журналу сопровождения.",
				},
				Snippet: "\"settings\": {\n  \"security_events_minimum_set\": \"true\",\n  \"security_log_has_event_id\": \"true\",\n  \"security_log_has_timestamp\": \"true\",\n  \"security_log_has_event_type\": \"true\",\n  \"security_event_importance\": \"true\"\n}",
			}),
		}
	case "BACKUP-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "backup-process",
			Title:     "Закрыть требования по резервному копированию и восстановлению",
			ApplyMode: "Оргмеры + backup pipeline",
			Target:    "Контур резервного копирования",
			Steps: []string{
				"Настроить регулярный backup базы и конфигурации СУБД.",
				"Определить срок хранения, шифрование и контроль доступа к резервным копиям.",
				"Провести и задокументировать тестовое восстановление.",
			},
			Snippet: "pg_dump -Fc -d <db_name> -f <backup_file>\n# либо настроить base backup / WAL archive по принятой схеме",
		})}
	case "AVAIL-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "availability-architecture",
			Title:     "Подтвердить или внедрить отказоустойчивую схему для требуемого класса",
			ApplyMode: "Архитектурное изменение",
			Target:    "Кластер, репликация и обновление",
			Steps: []string{
				"Определить целевую HA-схему: primary-standby, Patroni, etcd/Consul или другой утвержденный контур.",
				"Задокументировать rolling update и rollback без остановки кластера.",
				"Подтвердить синхронизацию конфигурации между узлами.",
			},
		})}
	case "MEM-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "memory-wipe-policy",
			Title:     "Закрыть требования по безопасному удалению данных и объектов",
			ApplyMode: "Оргмеры + защищенная утилизация",
			Target:    "Политика удаления данных",
			Steps: []string{
				"Определить процедуру безопасного удаления файлов БД, журналов и резервных копий.",
				"Подтвердить многократную перезапись или криптографическое уничтожение носителя.",
				"Отдельно описать удаление объектов БД для усиленных классов.",
			},
		})}
	case "PERF-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "performance-evidence",
			Title:     "Подтвердить документирование показателей производительности",
			ApplyMode: "Документация и эксплуатационные замеры",
			Target:    "Паспорт производительности СУБД",
			Steps: []string{
				"Зафиксировать измеренные показатели производительности и условия их получения.",
				"Подтвердить зависимость значений от параметров настройки и среды функционирования.",
				"Синхронизировать данные с эксплуатационной документацией и профилем объекта.",
			},
			Snippet: "\"settings\": {\n  \"performance_metrics_documented\": \"true\",\n  \"performance_dependencies_documented\": \"true\",\n  \"performance_operating_conditions_documented\": \"true\"\n}",
		})}
	case "ENV-001":
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "environment-hardening",
			Title:     "Ограничить программную среду и загрузку недоверенного кода",
			ApplyMode: "Оргмеры + hardening ОС и расширений",
			Target:    "Host OS и политика расширений",
			Steps: []string{
				"Утвердить allowlist для расширений PostgreSQL и вспомогательного ПО.",
				"Ограничить установку сторонних библиотек и процедур пользователями БД.",
				"Контролировать целостность бинарных файлов и shared libraries.",
			},
			Snippet: "\"settings\": {\n  \"allowlist_enabled\": \"true\",\n  \"block_untrusted_code_load\": \"true\",\n  \"block_modified_code_load\": \"true\"\n}",
		})}
	default:
		return []Proposal{mergeProposal(base, Proposal{
			Key:       "generic-" + finding.ID,
			Title:     "Устранить выявленное несоответствие: " + finding.Title,
			ApplyMode: "Ручная проработка",
			Target:    finding.Category,
			Steps: []string{
				"Сопоставить рекомендацию анализа с текущим регламентом и архитектурой объекта.",
				"Подготовить изменение конфигурации, SQL или эксплуатационной процедуры.",
				"Повторно запустить анализ живой БД после внесения изменений.",
			},
		})}
	}
}

func auditSafeLoggingProposal(base Proposal, snapshot model.ConfigSnapshot) Proposal {
	return mergeProposal(base, Proposal{
		Key:          "audit-safe-logging",
		Title:        "Включить безопасный базовый аудит PostgreSQL",
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
			"ALTER SYSTEM SET log_statement = 'ddl'",
		},
		Steps: []string{
			"Безопасно включить логирование подключений, отключений и ошибок.",
			"Ограничить доступ к журналам и включить ротацию, чтобы повысить готовность к требованиям ФСТЭК.",
			"Регистрировать DDL- и ролевые события (CREATE/ALTER/DROP, управление ролями) для покрытия обязательного набора событий безопасности.",
		},
		Snippet: "ALTER SYSTEM SET log_connections = 'on';\nALTER SYSTEM SET log_disconnections = 'on';\nALTER SYSTEM SET log_min_error_statement = 'error';\nALTER SYSTEM SET log_statement = 'ddl';\nSELECT pg_reload_conf();",
	})
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
	if len(extra.ControlRefs) == 0 {
		extra.ControlRefs = append([]string{}, base.ControlRefs...)
	}
	return extra
}

func collectControlRefs(proposals []Proposal) []string {
	seen := make(map[string]struct{})
	var refs []string
	for _, proposal := range proposals {
		for _, ref := range proposal.ControlRefs {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if _, exists := seen[ref]; exists {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

func controlRefsForFinding(id string) []string {
	switch id {
	case "TRUST-001":
		return []string{"Приказ ФСТЭК №64, п.5"}
	case "OS-001":
		return []string{"Приказ ФСТЭК №64, п.6"}
	case "ACCESS-001", "ACCESS-002", "ACCESS-003":
		return []string{"Приказ ФСТЭК №64, п.7.1"}
	case "AUTH-001", "AUTH-002":
		return []string{"Приказ ФСТЭК №64, пп.8.1-8.3"}
	case "INT-001":
		return []string{"Приказ ФСТЭК №64, п.9.1"}
	case "INT-002":
		return []string{"Приказ ФСТЭК №64, п.9.2"}
	case "AUD-001":
		return []string{"Приказ ФСТЭК №64, п.10.1"}
	case "AUD-002":
		return []string{"Приказ ФСТЭК №64, пп.10.1-10.2"}
	case "BACKUP-001":
		return []string{"Приказ ФСТЭК №64, пп.11.1-11.2"}
	case "AVAIL-001":
		return []string{"Приказ ФСТЭК №64, п.12"}
	case "MEM-001":
		return []string{"Приказ ФСТЭК №64, пп.13.1-13.2"}
	case "PERF-001":
		return []string{"Приказ ФСТЭК №64, п.14"}
	case "ENV-001":
		return []string{"Приказ ФСТЭК №64, пп.15.1-15.2"}
	default:
		return nil
	}
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

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
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
