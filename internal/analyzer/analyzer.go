//go:build ignore
// +build ignore

package analyzer

import (
	"fmt"
	"math"
	"strings"
	"time"

	"bd-scan/internal/model"
)

type Service struct{}

func (Service) Analyze(config model.NormalizedConfig, class model.ProtectionClass) model.AnalysisResult {
	profile := class.Profile()
	findings := []model.Finding{
		passwordEncryptionRule(config, profile),
		passwordLengthRule(config, profile),
		failedAttemptsRule(config, profile),
		hbaRule(config, profile),
		sslRule(config, profile),
		auditSubsystemRule(config, profile),
		securityLoggingRule(config, profile),
		roleSeparationRule(config),
		backupRule(config, profile),
		integrityRule(config, profile),
	}

	summary, score := summarize(findings)

	return model.AnalysisResult{
		Target:      config.Snapshot.Target,
		Class:       class,
		Profile:     profile,
		GeneratedAt: time.Now(),
		Summary:     summary,
		Score:       score,
		Findings:    findings,
		Notes:       append([]string{}, config.Snapshot.CollectionWarnings...),
	}
}

func passwordEncryptionRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("AUTH-001", "Политика шифрования паролей", "Аутентификация", model.SeverityHigh,
		"Профиль контроля должен подтверждать использование стойкого механизма хранения паролей.",
		"Использование устаревших схем хранения паролей упрощает подбор и компрометацию учетных записей.",
		"Установите password_encryption = 'scram-sha-256' и обновите пароли пользователей.")

	value := config.Param("password_encryption")
	switch {
	case value == "":
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityMedium
		finding.Evidence = []string{"Параметр password_encryption не обнаружен в доступных источниках."}
	case value == "scram-sha-256":
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Обнаружено значение password_encryption = scram-sha-256."}
	case profile.RequireSCRAM:
		finding.Status = model.StatusFail
		finding.Evidence = []string{fmt.Sprintf("Для выбранного профиля требуется SCRAM, но обнаружено значение %q.", value)}
	default:
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityMedium
		finding.Evidence = []string{fmt.Sprintf("Обнаружено значение password_encryption = %q. Рекомендуется перейти на SCRAM.", value)}
	}

	return finding
}

func passwordLengthRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("AUTH-002", "Минимальная длина пароля", "Аутентификация", model.SeverityMedium,
		"Профиль контроля должен подтверждать минимальную длину пароля для учетных записей СУБД.",
		"Короткие пароли значительно повышают риск успешного перебора.",
		"Зафиксируйте и примените минимальную длину пароля не ниже значения профильного порога.")

	value, ok := config.IntParam("password_min_length")
	if !ok {
		finding.Status = model.StatusWarn
		finding.Evidence = []string{"Параметр password_min_length отсутствует. Обычно он передается через metadata JSON или внешний модуль политики."}
		return finding
	}

	if value < profile.MinPasswordLength {
		finding.Status = model.StatusFail
		finding.Evidence = []string{fmt.Sprintf("Обнаружено значение password_min_length = %d при требуемом пороге %d.", value, profile.MinPasswordLength)}
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{fmt.Sprintf("Минимальная длина пароля %d соответствует профилю %s.", value, profile.Class.String())}
	return finding
}

func failedAttemptsRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("AUTH-003", "Ограничение неуспешных попыток входа", "Аутентификация", model.SeverityMedium,
		"Необходимо ограничивать число подряд неуспешных попыток аутентификации.",
		"Отсутствие лимита облегчает перебор учетных данных.",
		"Настройте внешний механизм блокировки или добавьте параметр auth_max_failed_attempts в metadata JSON.")

	value, ok := config.IntParam("auth_max_failed_attempts")
	if !ok {
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityLow
		finding.Evidence = []string{"Лимит неуспешных попыток входа не подтвержден доступными данными."}
		return finding
	}

	if value > profile.MaxFailedAuthAttempts {
		finding.Status = model.StatusFail
		finding.Evidence = []string{fmt.Sprintf("Обнаружено значение auth_max_failed_attempts = %d, что выше допустимого порога %d.", value, profile.MaxFailedAuthAttempts)}
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{fmt.Sprintf("Лимит неуспешных попыток входа установлен на уровне %d.", value)}
	return finding
}

func hbaRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("ACCESS-001", "Правила клиентской аутентификации pg_hba.conf", "Управление доступом", model.SeverityCritical,
		"Правила доступа должны исключать заведомо небезопасные методы аутентификации и чрезмерно широкие разрешения.",
		"Слабые методы аутентификации и широкие сетевые правила открывают путь к несанкционированному доступу.",
		"Исключите методы trust/password, ограничьте адресные диапазоны и переведите клиентов на scram-sha-256.")

	if len(config.Snapshot.HBARules) == 0 {
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityHigh
		finding.Evidence = []string{"Правила pg_hba.conf не были загружены, поэтому оценка клиентской аутентификации неполная."}
		return finding
	}

	var evidence []string
	status := model.StatusPass

	for _, rule := range config.WeakHBARules {
		evidence = append(evidence, fmt.Sprintf("Строка %d: обнаружен метод %s (%s).", rule.SourceLine, rule.Method, rule.Raw))
		if rule.Method == "trust" || rule.Method == "password" || profile.RequireSCRAM {
			status = model.StatusFail
		} else if status == model.StatusPass {
			status = model.StatusWarn
		}
	}

	for _, rule := range config.OpenHBARules {
		evidence = append(evidence, fmt.Sprintf("Строка %d: широкое правило доступа (%s).", rule.SourceLine, rule.Raw))
		if status == model.StatusPass {
			status = model.StatusWarn
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Небезопасные и чрезмерно широкие правила в pg_hba.conf не обнаружены."}
		return finding
	}

	finding.Status = status
	finding.Evidence = evidence
	return finding
}

func sslRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("NET-001", "Шифрование сетевого взаимодействия", "Сетевое взаимодействие", model.SeverityHigh,
		"Для профилей повышенной защищенности должен использоваться защищенный канал подключения к СУБД.",
		"Передача данных без TLS повышает риск перехвата учетных данных и служебной информации.",
		"Включите ssl = on и используйте только защищенные правила hostssl в pg_hba.conf.")

	value, ok := config.BoolParam("ssl")
	if !ok {
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityMedium
		finding.Evidence = []string{"Параметр ssl не был обнаружен."}
		return finding
	}

	if profile.RequireSSL && !value {
		finding.Status = model.StatusFail
		finding.Evidence = []string{"Для выбранного профиля требуется TLS, но ssl = off."}
		return finding
	}

	if !profile.RequireSSL && !value {
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityLow
		finding.Evidence = []string{"ssl = off. Для базового профиля это допустимо, но не рекомендуется."}
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{"Шифрование сетевого взаимодействия включено: ssl = on."}
	return finding
}

func auditSubsystemRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("AUD-001", "Наличие подсистемы аудита", "Регистрация событий", model.SeverityHigh,
		"Необходимо подтверждать наличие механизмов регистрации событий безопасности и действий привилегированных пользователей.",
		"Без аудита затрудняется выявление инцидентов и расследование компрометации.",
		"Подключите pgAudit или аналогичный механизм и зафиксируйте профиль аудита в metadata JSON.")

	if config.HasPgAudit {
		finding.Status = model.StatusPass
		evidence := []string{"Подсистема аудита обнаружена."}
		if config.Snapshot.Audit.Provider != "" {
			evidence = append(evidence, fmt.Sprintf("Провайдер аудита: %s.", config.Snapshot.Audit.Provider))
		}
		if len(config.Snapshot.Audit.Events) > 0 {
			evidence = append(evidence, fmt.Sprintf("Категории аудита: %s.", strings.Join(config.Snapshot.Audit.Events, ", ")))
		}
		finding.Evidence = evidence
		return finding
	}

	if profile.RequireAudit {
		finding.Status = model.StatusFail
		finding.Evidence = []string{"Не удалось подтвердить включение подсистемы аудита для выбранного профиля."}
		return finding
	}

	finding.Status = model.StatusWarn
	finding.Severity = model.SeverityLow
	finding.Evidence = []string{"Подсистема аудита не подтверждена. Для базового профиля это отмечено как улучшение."}
	return finding
}

func securityLoggingRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("AUD-002", "Полнота журналирования событий безопасности", "Регистрация событий", model.SeverityMedium,
		"Журналы должны фиксировать подключения, отключения и ошибки, значимые для расследования инцидентов.",
		"Неполное журналирование делает незаметными попытки компрометации и злоупотребления полномочиями.",
		"Включите log_connections, log_disconnections и настройте log_min_error_statement не выше error.")

	logConnections, okConn := config.BoolParam("log_connections")
	logDisconnections, okDisconn := config.BoolParam("log_disconnections")
	logErrors := config.Param("log_min_error_statement")

	var evidence []string
	if !okConn || !logConnections {
		evidence = append(evidence, "Подтверждение log_connections = on отсутствует.")
	}
	if !okDisconn || !logDisconnections {
		evidence = append(evidence, "Подтверждение log_disconnections = on отсутствует.")
	}
	if !isErrorLevelOrStricter(logErrors) {
		evidence = append(evidence, fmt.Sprintf("Текущее значение log_min_error_statement = %q.", logErrors))
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подключения, отключения и ошибки фиксируются в журнале."}
		return finding
	}

	if profile.RequireAudit {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func roleSeparationRule(config model.NormalizedConfig) model.Finding {
	finding := baseFinding("ACCESS-002", "Разграничение привилегий и избыточные роли", "Управление доступом", model.SeverityHigh,
		"Административные и прикладные роли должны быть разделены, а права public и суперпользователей ограничены.",
		"Избыточные привилегии ускоряют развитие инцидента после компрометации одной учетной записи.",
		"Сократите число суперпользователей, пересмотрите роль public и отключите ненужные атрибуты replication/bypassrls.")

	if len(config.Snapshot.Roles) == 0 {
		finding.Status = model.StatusWarn
		finding.Severity = model.SeverityMedium
		finding.Evidence = []string{"Сведения о ролях не были предоставлены. Добавьте metadata JSON с перечнем ролей и их атрибутов."}
		return finding
	}

	superusers := 0
	var evidence []string
	var superuserNames []string
	for _, role := range config.Snapshot.Roles {
		if role.Superuser {
			superusers++
			superuserNames = append(superuserNames, role.Name)
		}
		if role.BypassRLS {
			evidence = append(evidence, fmt.Sprintf("Роль %s обладает атрибутом BYPASSRLS.", role.Name))
		}
		if role.Replication {
			evidence = append(evidence, fmt.Sprintf("Роль %s обладает атрибутом REPLICATION.", role.Name))
		}
		if strings.EqualFold(role.Name, "public") && len(role.Privileges) > 0 {
			evidence = append(evidence, fmt.Sprintf("Роль public содержит привилегии: %s.", strings.Join(role.Privileges, ", ")))
		}
	}

	if superusers > 1 {
		for _, name := range superuserNames {
			evidence = append(evidence, fmt.Sprintf("Роль %s обладает атрибутом SUPERUSER.", name))
		}
	} else if superusers == 1 && len(superuserNames) == 1 && !strings.EqualFold(superuserNames[0], "postgres") {
		evidence = append(evidence, fmt.Sprintf("Роль %s обладает атрибутом SUPERUSER.", superuserNames[0]))
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Критичных отклонений по привилегированным ролям не обнаружено."}
		return finding
	}

	if superusers > 1 {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func backupRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("BACKUP-001", "Резервное копирование", "Восстановление", model.SeverityHigh,
		"Должны быть подтверждены наличие резервного копирования и возможность восстановления.",
		"Отсутствие резервных копий делает невозможным восстановление после инцидента или отказа.",
		"Организуйте регулярное резервное копирование, контроль срока хранения и тестовые восстановления.")

	backup := config.Snapshot.Backup
	if !backup.Enabled {
		if profile.RequireBackup {
			finding.Status = model.StatusFail
			finding.Evidence = []string{"Резервное копирование не подтверждено."}
		} else {
			finding.Status = model.StatusWarn
			finding.Evidence = []string{"Резервное копирование не подтверждено доступными данными."}
		}
		return finding
	}

	var evidence []string
	if backup.Schedule == "" {
		evidence = append(evidence, "Не указана периодичность резервного копирования.")
	}
	if backup.RetentionDays < 7 {
		evidence = append(evidence, fmt.Sprintf("Срок хранения резервных копий составляет %d дней.", backup.RetentionDays))
	}
	if !backup.TestedRestore {
		evidence = append(evidence, "Не подтверждено тестовое восстановление из резервной копии.")
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{fmt.Sprintf("Резервное копирование включено, расписание: %s, срок хранения: %d дней.", backup.Schedule, backup.RetentionDays)}
		return finding
	}

	finding.Status = model.StatusWarn
	finding.Evidence = evidence
	return finding
}

func integrityRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding("INT-001", "Контроль целостности конфигурации", "Контроль целостности", model.SeverityMedium,
		"Необходимо подтверждать механизмы контроля целостности конфигурационных файлов и данных.",
		"Незаметное изменение конфигурации может отключить защитные механизмы или создать скрытый канал доступа.",
		"Зафиксируйте контроль целостности конфигурации и, при возможности, включите checksums на уровне кластера.")

	integrity := config.Snapshot.Integrity
	if integrity.ConfigControlEnabled && integrity.ChecksumsEnabled {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Контроль целостности конфигурации и checksums подтверждены."}
		return finding
	}

	var evidence []string
	if !integrity.ConfigControlEnabled {
		evidence = append(evidence, "Не подтвержден контроль целостности конфигурационных файлов.")
	}
	if !integrity.ChecksumsEnabled {
		evidence = append(evidence, "Не подтверждено использование checksums данных.")
	}

	if profile.Class <= model.Class4 {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func summarize(findings []model.Finding) (model.Summary, int) {
	var summary model.Summary
	totalWeight := 0
	penalty := 0.0

	for _, finding := range findings {
		weight := finding.Severity.Weight()
		totalWeight += weight

		switch finding.Status {
		case model.StatusPass:
			summary.Passed++
		case model.StatusWarn:
			summary.Warnings++
			penalty += float64(weight) * 0.5
		case model.StatusFail:
			summary.Failed++
			penalty += float64(weight)
		}
	}

	if totalWeight == 0 {
		return summary, 100
	}

	score := int(math.Round((1 - penalty/float64(totalWeight)) * 100))
	if score < 0 {
		score = 0
	}

	return summary, score
}

func baseFinding(id, title, category string, severity model.Severity, requirement, risk, recommendation string) model.Finding {
	return model.Finding{
		ID:             id,
		Title:          title,
		Category:       category,
		Severity:       severity,
		Requirement:    requirement,
		Risk:           risk,
		Recommendation: recommendation,
	}
}

func isErrorLevelOrStricter(level string) bool {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "panic", "fatal", "error":
		return true
	default:
		return false
	}
}
