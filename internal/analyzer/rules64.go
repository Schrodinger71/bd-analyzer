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
		trustLevelRule(config, profile),
		operatingSystemRule(config, profile),
		accessMethodsRule(config, profile),
		roleModelRule(config),
		accessMatrixRule(config),
		passwordPolicyRule(config, profile),
		authLifecycleRule(config),
		integrityBaseRule(config, profile),
		integrityRuntimeRule(config, profile),
		auditMechanismRule(config, profile),
		auditCoverageRule(config, profile),
		backupRule(config, profile),
		availabilityRule(config, profile),
		memoryWipeRule(config, profile),
		performanceRule(config),
		programEnvironmentRule(config, profile),
	}

	summary, score := summarize(findings)

	notes := append([]string{}, config.Snapshot.CollectionWarnings...)
	notes = append(notes, config.Snapshot.Notes...)
	if class == model.Class1 || class == model.Class2 || class == model.Class3 {
		notes = append(notes, "Для классов 1-3 в текущей версии применяется усиленный профиль проверок не ниже требований 4 класса, так как в предоставленной выписке приказа №64 детализированы требования для классов 6, 5 и 4.")
	}

	return model.AnalysisResult{
		Target:      config.Snapshot.Target,
		Class:       class,
		Profile:     profile,
		GeneratedAt: time.Now(),
		Summary:     summary,
		Score:       score,
		Findings:    findings,
		Notes:       notes,
	}
}

func trustLevelRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"TRUST-001",
		"Уровень доверия СУБД",
		"Уровень доверия",
		model.SeverityHigh,
		"Пункт 5 приказа №64 требует соответствия класса защиты СУБД установленному уровню доверия.",
		"Недостаточный уровень доверия означает несоответствие нормативным требованиям к сертифицированной СУБД.",
		"Подтвердите уровень доверия сертификационными документами и укажите его в metadata JSON через параметр dbms_trust_level.",
	)

	value, ok := config.IntParam("dbms_trust_level")
	if !ok {
		finding.Status = model.StatusWarn
		finding.Evidence = []string{"Не удалось подтвердить уровень доверия СУБД по доступным данным. Ожидается параметр dbms_trust_level."}
		return finding
	}

	if value < profile.RequiredTrustLevel {
		finding.Status = model.StatusFail
		finding.Evidence = []string{fmt.Sprintf("Указан уровень доверия %d при требуемом не ниже %d.", value, profile.RequiredTrustLevel)}
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{fmt.Sprintf("Уровень доверия %d соответствует требованию для %s.", value, profile.Class.String())}
	return finding
}

func operatingSystemRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"OS-001",
		"Сертифицированная операционная система",
		"Операционная система",
		model.SeverityCritical,
		"Пункт 6 приказа №64 требует функционирования СУБД в сертифицированной операционной системе с классом защиты не ниже класса защиты СУБД.",
		"Использование неподтвержденной ОС или ОС с более низким классом защиты нарушает обязательные требования приказа.",
		"Подтвердите сертификацию ОС и задайте в metadata JSON параметры os_certified и os_protection_class.",
	)

	osCertified, hasCertified := config.BoolParam("os_certified")
	osClass, hasClass := config.IntParam("os_protection_class")

	if !hasCertified || !hasClass {
		var evidence []string
		if !hasCertified {
			evidence = append(evidence, "Нет подтверждения сертификации ОС: отсутствует параметр os_certified.")
		}
		if !hasClass {
			evidence = append(evidence, "Нет подтверждения класса защиты ОС: отсутствует параметр os_protection_class.")
		}
		finding.Status = model.StatusWarn
		finding.Evidence = evidence
		return finding
	}

	var evidence []string
	if !osCertified {
		evidence = append(evidence, "Операционная система отмечена как несертифицированная.")
	}
	if osClass < int(profile.Class) {
		evidence = append(evidence, fmt.Sprintf("Класс защиты ОС %d ниже класса защиты СУБД %d.", osClass, profile.Class))
	}
	if len(evidence) > 0 {
		finding.Status = model.StatusFail
		finding.Evidence = evidence
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{fmt.Sprintf("Подтверждена сертифицированная ОС с классом защиты %d.", osClass)}
	return finding
}

func accessMethodsRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"ACCESS-001",
		"Дискреционный и ролевой доступ",
		"Управление доступом",
		model.SeverityCritical,
		"Пункт 7.1 приказа №64 требует реализации дискреционного и ролевого методов управления доступом.",
		"Отсутствие DAC или RBAC делает разграничение доступа неполным и затрудняет исполнение ролевой модели безопасности.",
		"Подтвердите реализацию DAC/RBAC параметрами access_dac_enabled и access_rbac_enabled.",
	)

	dac, hasDAC := config.BoolParam("access_dac_enabled")
	rbac, hasRBAC := config.BoolParam("access_rbac_enabled")

	var evidence []string
	if !hasDAC {
		evidence = append(evidence, "Не подтверждена реализация дискреционного доступа: отсутствует access_dac_enabled.")
	} else if profile.RequireDAC && !dac {
		evidence = append(evidence, "Дискреционный метод управления доступом отключен или не реализован.")
	}

	if !hasRBAC {
		evidence = append(evidence, "Не подтверждена реализация ролевого доступа: отсутствует access_rbac_enabled.")
	} else if profile.RequireRBAC && !rbac {
		evidence = append(evidence, "Ролевой метод управления доступом отключен или не реализован.")
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждена реализация дискреционного и ролевого методов управления доступом."}
		return finding
	}

	if (hasDAC && !dac) || (hasRBAC && !rbac) {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func roleModelRule(config model.NormalizedConfig) model.Finding {
	finding := baseFinding(
		"ACCESS-002",
		"Ролевая модель администрирования",
		"Управление доступом",
		model.SeverityHigh,
		"Пункт 7.1 приказа №64 требует наличия ролей администратора СУБД, администратора базы данных и пользователя базы данных с соответствующими полномочиями.",
		"Неполная ролевая модель приводит к смешению обязанностей и избыточным привилегиям.",
		"Подтвердите состав ролей и полноту их прав параметрами role_dbms_admin_present, role_db_admin_present, role_db_user_present, dbms_admin_rights_complete, db_admin_rights_complete и db_user_rights_complete.",
	)

	var evidence []string
	fail := false
	missing := false

	checks := []struct {
		param  string
		label  string
		failed string
	}{
		{"role_dbms_admin_present", "роль администратора СУБД", "Не подтверждено наличие роли администратора СУБД."},
		{"role_db_admin_present", "роль администратора базы данных", "Не подтверждено наличие роли администратора базы данных."},
		{"role_db_user_present", "роль пользователя базы данных", "Не подтверждено наличие роли пользователя базы данных."},
		{"dbms_admin_rights_complete", "полномочия администратора СУБД", "Полномочия администратора СУБД заданы не в полном объеме."},
		{"db_admin_rights_complete", "полномочия администратора базы данных", "Полномочия администратора базы данных заданы не в полном объеме."},
		{"db_user_rights_complete", "полномочия пользователя базы данных", "Полномочия пользователя базы данных заданы не в полном объеме."},
	}

	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			missing = true
			evidence = append(evidence, fmt.Sprintf("Нет подтверждения для %s: отсутствует параметр %s.", check.label, check.param))
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.failed)
		}
	}

	superusers := 0
	var superuserNames []string
	for _, role := range config.Snapshot.Roles {
		if role.Superuser {
			superusers++
			superuserNames = append(superuserNames, role.Name)
		}
	}
	if superusers > 1 {
		fail = true
		evidence = append(evidence, fmt.Sprintf("В PostgreSQL обнаружено несколько SUPERUSER-ролей: %s.", strings.Join(superuserNames, ", ")))
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждена требуемая ролевая модель и полнота административных полномочий."}
		return finding
	}

	if false {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Механизм аудита подтвержден, а большинство защитных свойств журнала настроено и готово к проверке."}
		return finding
	}

	if false && !fail {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Механизм аудита подтвержден, а большинство защитных свойств журнала настроено и готово к проверке."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else if missing {
		finding.Status = model.StatusWarn
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func accessMatrixRule(config model.NormalizedConfig) model.Finding {
	finding := baseFinding(
		"ACCESS-003",
		"Матрицы доступа к объектам и процедурам",
		"Управление доступом",
		model.SeverityHigh,
		"Пункт 7.1 приказа №64 требует настраиваемых списков управления доступом к объектам и процедурам базы данных.",
		"Если система не поддерживает ACL для процедур и объектов, разграничение доступа не соответствует нормативным требованиям.",
		"Подтвердите поддержку матриц доступа параметрами procedure_acl_supported и object_acl_supported.",
	)

	procACL, hasProcACL := config.BoolParam("procedure_acl_supported")
	objACL, hasObjACL := config.BoolParam("object_acl_supported")

	var evidence []string
	fail := false

	if !hasProcACL {
		evidence = append(evidence, "Не подтверждена поддержка ACL для процедур: отсутствует procedure_acl_supported.")
	} else if !procACL {
		fail = true
		evidence = append(evidence, "Не поддерживается разграничение доступа к созданию, изменению, удалению и выполнению процедур.")
	}

	if !hasObjACL {
		evidence = append(evidence, "Не подтверждена поддержка ACL для объектов доступа: отсутствует object_acl_supported.")
	} else if !objACL {
		fail = true
		evidence = append(evidence, "Не поддерживается разграничение доступа к созданию, изменению, удалению и чтению объектов базы данных.")
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждена поддержка матриц доступа для процедур и объектов базы данных."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func passwordPolicyRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"AUTH-001",
		"Парольная политика и лимит попыток входа",
		"Аутентификация",
		model.SeverityCritical,
		"Пункты 8.1-8.3 приказа №64 задают минимальную длину пароля, минимальный размер алфавита и максимальное число неуспешных попыток аутентификации.",
		"Слабая парольная политика и завышенный порог попыток входа увеличивают риск подбора учетных данных.",
		"Укажите в metadata JSON параметры password_min_length, password_alphabet_size и auth_max_failed_attempts в соответствии с выбранным классом защиты.",
	)

	length, hasLength := config.IntParam("password_min_length")
	alphabet, hasAlphabet := config.IntParam("password_alphabet_size")
	attempts, hasAttempts := config.IntParam("auth_max_failed_attempts")

	var evidence []string
	fail := false

	if !hasLength {
		evidence = append(evidence, "Не удалось подтвердить минимальную длину пароля: отсутствует password_min_length.")
	} else if length < profile.MinPasswordLength {
		fail = true
		evidence = append(evidence, fmt.Sprintf("Минимальная длина пароля %d ниже требуемой %d.", length, profile.MinPasswordLength))
	}

	if !hasAlphabet {
		evidence = append(evidence, "Не удалось подтвердить размер алфавита пароля: отсутствует password_alphabet_size.")
	} else if alphabet < profile.MinPasswordAlphabet {
		fail = true
		evidence = append(evidence, fmt.Sprintf("Размер алфавита пароля %d ниже требуемого %d.", alphabet, profile.MinPasswordAlphabet))
	}

	if !hasAttempts {
		evidence = append(evidence, "Не удалось подтвердить лимит неуспешных попыток входа: отсутствует auth_max_failed_attempts.")
	} else if attempts > profile.MaxFailedAuthAttempts {
		fail = true
		evidence = append(evidence, fmt.Sprintf("Максимальное число неуспешных попыток %d выше допустимого %d.", attempts, profile.MaxFailedAuthAttempts))
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{
			fmt.Sprintf("Парольная политика подтверждена: длина %d, алфавит %d, лимит неуспешных попыток %d.", length, alphabet, attempts),
		}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func authLifecycleRule(config model.NormalizedConfig) model.Finding {
	finding := baseFinding(
		"AUTH-002",
		"Жизненный цикл аутентификации",
		"Аутентификация",
		model.SeverityHigh,
		"Пункт 8.1 приказа №64 требует смены первичного пароля, блокировки учетной записи после исчерпания попыток входа, маскирования пароля и защищенного хранения аутентификационной информации.",
		"Нарушение этих требований упрощает компрометацию учетных записей и эксплуатацию первичных паролей.",
		"Подтвердите параметры password_change_on_first_login, auth_lockout_enabled, auth_unlock_supported, password_input_masking и auth_storage_protected.",
	)

	var evidence []string
	fail := false

	checks := []struct {
		param        string
		failMessage  string
		warnMessage  string
		acceptFromDB bool
	}{
		{"password_change_on_first_login", "Смена пароля после первичной аутентификации отключена.", "Нет подтверждения смены пароля после первичной аутентификации.", false},
		{"auth_lockout_enabled", "Механизм блокировки после неуспешных попыток отключен.", "Нет подтверждения механизма блокировки после неуспешных попыток.", false},
		{"auth_unlock_supported", "Не поддерживается разблокировка учетной записи администратором или по таймауту.", "Нет подтверждения механизма разблокировки учетной записи.", false},
		{"password_input_masking", "Маскирование пароля при вводе отключено.", "Нет подтверждения маскирования пароля при вводе.", false},
		{"auth_storage_protected", "Хранение аутентификационной информации не защищено.", "Нет подтверждения защищенного хранения аутентификационной информации.", true},
	}

	passwordEncryption := config.Param("password_encryption")
	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok && check.acceptFromDB && passwordEncryption == "scram-sha-256" {
			value = true
			ok = true
			evidence = append(evidence, "Защищенное хранение частично подтверждено параметром password_encryption = scram-sha-256.")
		}
		if !ok && check.acceptFromDB && passwordEncryption == "md5" {
			evidence = append(evidence, "Обнаружено password_encryption = md5, но этого недостаточно для подтверждения защищенного хранения аутентификационной информации.")
		}
		if !ok {
			evidence = append(evidence, check.warnMessage)
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.failMessage)
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены механизмы смены первичного пароля, блокировки, разблокировки, маскирования и защищенного хранения аутентификационной информации."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func integrityBaseRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"INT-001",
		"Контроль целостности при запуске",
		"Контроль целостности",
		model.SeverityCritical,
		"Пункт 9.1 приказа №64 требует контроля целостности конфигурации и процедур, уведомления администраторов и блокирования доступа пользователей при нарушении целостности.",
		"Отсутствие контроля целостности позволяет скрытно модифицировать конфигурацию и программный код СУБД.",
		"Подтвердите настройки snapshot.Integrity и параметры integrity_alert_dbms_admin, integrity_alert_db_admin, integrity_block_system_users, integrity_block_db_users.",
	)

	var evidence []string
	fail := false

	if !config.Snapshot.Integrity.ConfigControlEnabled {
		if profile.RequireIntegrityBlocking {
			fail = true
		}
		evidence = append(evidence, "Не подтвержден контроль целостности конфигурации СУБД и баз данных при запуске.")
	}

	checks := []struct {
		param string
		text  string
	}{
		{"integrity_alert_dbms_admin", "Не подтверждено уведомление администратора СУБД о нарушении целостности."},
		{"integrity_alert_db_admin", "Не подтверждено уведомление администратора базы данных о нарушении целостности."},
		{"integrity_block_system_users", "Не подтверждено блокирование доступа пользователей СУБД при нарушении целостности."},
		{"integrity_block_db_users", "Не подтверждено блокирование доступа пользователей базы данных при нарушении целостности."},
	}

	allExplicit := config.Snapshot.Integrity.ConfigControlEnabled
	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			allExplicit = false
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			allExplicit = false
			fail = true
			evidence = append(evidence, check.text)
		}
	}

	if allExplicit {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтвержден контроль целостности, уведомление администраторов и блокирование доступа при нарушении целостности."}
		return finding
	}

	if config.Snapshot.Integrity.ChecksumsEnabled {
		evidence = append(evidence, "Дополнительное подтверждение: checksums для кластера включены.")
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func integrityRuntimeRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"INT-002",
		"Периодический контроль целостности в работе",
		"Контроль целостности",
		model.SeverityHigh,
		"Пункт 9.2 приказа №64 требует для 4 класса защиты контроля целостности процедур в процессе функционирования не реже одного раза в сутки.",
		"Отсутствие регулярной проверки целостности уменьшает вероятность своевременного выявления модификации кода.",
		"Для 4 класса задайте параметр integrity_runtime_daily = true.",
	)

	if !profile.RequireIntegrityRuntime {
		finding.Status = model.StatusPass
		finding.Severity = model.SeverityLow
		finding.Evidence = []string{"Для выбранного класса защиты суточный контроль целостности в процессе функционирования не является дополнительным требованием приказа."}
		return finding
	}

	value, ok := config.BoolParam("integrity_runtime_daily")
	if !ok {
		finding.Status = model.StatusWarn
		finding.Evidence = []string{"Не удалось подтвердить суточный контроль целостности в процессе функционирования: отсутствует integrity_runtime_daily."}
		return finding
	}

	if !value {
		finding.Status = model.StatusFail
		finding.Evidence = []string{"Суточный контроль целостности в процессе функционирования не реализован."}
		return finding
	}

	finding.Status = model.StatusPass
	finding.Evidence = []string{"Подтвержден контроль целостности процедур в процессе функционирования не реже одного раза в сутки."}
	return finding
}

func auditMechanismRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"AUD-001",
		"Механизмы регистрации событий безопасности",
		"Регистрация событий безопасности",
		model.SeverityCritical,
		"Пункт 10.1 приказа №64 требует регистрации событий безопасности, оповещения администраторов, структурированного журнала, ограничения доступа к журналу и архивирования при заполнении.",
		"Без надежного журнала событий безопасность СУБД становится плохо контролируемой и усложняется расследование инцидентов.",
		"Подтвердите audit subsystem и параметры security_event_alerting, security_log_structured, security_log_read_restricted, security_log_archive_on_full.",
	)

	explicitAudit, hasExplicitAudit := config.BoolParam("security_audit_enabled")
	auditEnabled := config.HasPgAudit || config.Snapshot.Audit.Enabled || (hasExplicitAudit && explicitAudit)

	var evidence []string
	fail := false

	if hasExplicitAudit && !explicitAudit {
		fail = true
		evidence = append(evidence, "Подсистема регистрации событий безопасности явно отключена.")
	} else if auditEnabled {
		if config.Snapshot.Audit.Provider != "" {
			evidence = append(evidence, fmt.Sprintf("Подсистема аудита подтверждена: %s.", config.Snapshot.Audit.Provider))
		} else {
			evidence = append(evidence, "Подсистема аудита подтверждена доступными данными.")
		}
	} else {
		evidence = append(evidence, "Не удалось подтвердить наличие подсистемы регистрации событий безопасности.")
	}

	checks := []struct {
		param string
		text  string
	}{
		{"security_event_alerting", "Не подтверждено оповещение администраторов о событиях безопасности."},
		{"security_log_structured", "Не подтвержден структурированный формат журнала событий безопасности."},
		{"security_log_read_restricted", "Не подтверждено ограничение доступа к журналу событий безопасности."},
		{"security_log_archive_on_full", "Не подтверждено архивирование журнала при исчерпании выделенной области памяти."},
	}

	allConfirmed := auditEnabled
	confirmedControls := 0
	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			allConfirmed = false
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			allConfirmed = false
			fail = true
			evidence = append(evidence, check.text)
			continue
		}
		confirmedControls++
	}

	if allConfirmed {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены регистрация событий безопасности, оповещение администраторов, структурированный журнал, ограничение доступа и архивирование при заполнении."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else if profile.RequireAudit {
		finding.Status = model.StatusWarn
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func auditCoverageRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"AUD-002",
		"Полнота состава и реквизитов журнала событий",
		"Регистрация событий безопасности",
		model.SeverityHigh,
		"Пункты 10.1-10.2 приказа №64 требуют регистрации минимального набора событий, уникального идентификатора, даты, времени, типа события и для 4 класса - сведений о важности события.",
		"Неполный состав журнала не позволяет достоверно фиксировать и интерпретировать события безопасности.",
		"Подтвердите параметры security_events_minimum_set, security_log_has_event_id, security_log_has_timestamp, security_log_has_event_type и для 4 класса security_event_importance.",
	)

	var evidence []string
	fail := false

	checks := []struct {
		param string
		text  string
	}{
		{"security_events_minimum_set", "Не подтверждена регистрация минимального обязательного набора событий безопасности."},
		{"security_log_has_event_id", "Не подтверждена регистрация уникального идентификатора события."},
		{"security_log_has_timestamp", "Не подтверждена регистрация даты и времени события."},
		{"security_log_has_event_type", "Не подтверждена регистрация типа события безопасности."},
	}

	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.text)
		}
	}

	if profile.RequireAuditImportance {
		value, ok := config.BoolParam("security_event_importance")
		if !ok {
			evidence = append(evidence, "Не подтверждена регистрация важности события для 4 класса защиты: отсутствует security_event_importance.")
		} else if !value {
			fail = true
			evidence = append(evidence, "Для 4 класса защиты журнал не содержит сведения о важности события.")
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены обязательный состав событий и реквизиты записей журнала безопасности."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func backupRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"BACKUP-001",
		"Резервное копирование и восстановление",
		"Резервное копирование",
		model.SeverityCritical,
		"Пункты 11.1-11.2 приказа №64 требуют резервного копирования и восстановления баз данных и конфигураций, а для 4 класса - дополнительно конфигурации самой СУБД.",
		"Отсутствие резервных копий и проверенного восстановления не позволяет обеспечить восстановление после инцидента или сбоя.",
		"Подтвердите backup settings и при необходимости параметр backup_config_included.",
	)

	backup := config.Snapshot.Backup
	var evidence []string
	fail := false

	if !backup.Enabled {
		evidence = append(evidence, "Резервное копирование баз данных не подтверждено.")
		fail = true
	}
	if backup.Enabled && !backup.TestedRestore {
		evidence = append(evidence, "Не подтверждено восстановление из резервной копии.")
		fail = true
	}
	if backup.Enabled && backup.Schedule == "" {
		evidence = append(evidence, "Не указано расписание резервного копирования.")
	}

	if profile.RequireConfigBackup {
		configBackup, ok := config.BoolParam("backup_config_included")
		if !ok {
			evidence = append(evidence, "Для 4 класса не подтверждено резервное копирование конфигурации СУБД: отсутствует backup_config_included.")
		} else if !configBackup {
			fail = true
			evidence = append(evidence, "Для 4 класса конфигурация СУБД не включена в резервное копирование.")
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены резервное копирование, восстановление и, при необходимости, копирование конфигурации СУБД."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func availabilityRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"AVAIL-001",
		"Отказоустойчивость и доступность",
		"Доступность",
		model.SeverityHigh,
		"Пункт 12 приказа №64 требует для 4 класса отказоустойчивый кластер, синхронизацию конфигурации, поочередное обновление и откат без остановки кластера.",
		"Недостаточная отказоустойчивость нарушает требования по доступности и затрудняет безопасное обновление СУБД.",
		"Для 4 класса подтвердите cluster_enabled, cluster_config_sync, rolling_update_supported и rollback_without_downtime.",
	)

	if !profile.RequireCluster {
		finding.Status = model.StatusPass
		finding.Severity = model.SeverityLow
		finding.Evidence = []string{"Для выбранного класса приказ №64 не вводит дополнительные требования по отказоустойчивому кластеру."}
		return finding
	}

	var evidence []string
	fail := false

	checks := []struct {
		param string
		text  string
	}{
		{"cluster_enabled", "Отказоустойчивый кластер для СУБД не подтвержден."},
		{"cluster_config_sync", "Не подтверждена синхронизация параметров конфигурации в кластере."},
		{"rolling_update_supported", "Не подтверждена возможность поочередного обновления узлов без потери доступности."},
		{"rollback_without_downtime", "Не подтверждена возможность отката обновления без прерывания работы кластера."},
	}

	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.text)
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены требования по отказоустойчивому кластеру и безопасному обновлению для 4 класса защиты."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func memoryWipeRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"MEM-001",
		"Очистка памяти и безопасное удаление",
		"Очистка памяти",
		model.SeverityHigh,
		"Пункты 13.1-13.2 приказа №64 требуют многократной перезаписи при удалении баз данных и журналов, а для 4 класса - также удаления объектов базы данных с перезаписью.",
		"Небезопасное удаление оставляет остаточные данные, доступные для восстановления.",
		"Подтвердите параметры memory_wipe_db_and_logs и для 4 класса memory_wipe_db_objects.",
	)

	var evidence []string
	fail := false

	value, ok := config.BoolParam("memory_wipe_db_and_logs")
	if !ok {
		evidence = append(evidence, "Не подтверждено безопасное удаление баз данных и журналов: отсутствует memory_wipe_db_and_logs.")
	} else if !value {
		fail = true
		evidence = append(evidence, "Безопасное удаление баз данных и журналов не реализовано.")
	}

	if profile.RequireObjectMemoryWipe {
		value, ok = config.BoolParam("memory_wipe_db_objects")
		if !ok {
			evidence = append(evidence, "Для 4 класса не подтверждено безопасное удаление объектов базы данных: отсутствует memory_wipe_db_objects.")
		} else if !value {
			fail = true
			evidence = append(evidence, "Для 4 класса безопасное удаление объектов базы данных не реализовано.")
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждено безопасное удаление баз данных, журналов и, при необходимости, объектов базы данных."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func performanceRule(config model.NormalizedConfig) model.Finding {
	finding := baseFinding(
		"PERF-001",
		"Документирование параметров производительности",
		"Производительность",
		model.SeverityMedium,
		"Пункт 14 приказа №64 требует документирования показателей производительности и зависимости этих значений от параметров настройки и условий функционирования.",
		"Отсутствие подтвержденных параметров производительности затрудняет оценку пригодности СУБД и соответствие формуляру.",
		"Подтвердите документирование параметров performance_sessions_documented, performance_queries_documented, performance_transactions_documented, performance_latency_documented, performance_lb_instances_documented.",
	)

	var evidence []string
	fail := false
	checks := []struct {
		param string
		text  string
	}{
		{"performance_sessions_documented", "Не подтверждено документирование числа параллельных пользовательских сессий."},
		{"performance_queries_documented", "Не подтверждено документирование количества стандартных запросов в единицу времени."},
		{"performance_transactions_documented", "Не подтверждено документирование количества транзакций в единицу времени."},
		{"performance_latency_documented", "Не подтверждено документирование задержки выполнения стандартного запроса."},
		{"performance_lb_instances_documented", "Не подтверждено документирование числа экземпляров для балансировки нагрузки."},
	}

	for _, check := range checks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.text)
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждено документирование всех обязательных параметров производительности."}
		return finding
	}

	if fail {
		finding.Status = model.StatusFail
	} else {
		finding.Status = model.StatusWarn
	}
	finding.Evidence = evidence
	return finding
}

func programEnvironmentRule(config model.NormalizedConfig, profile model.ControlProfile) model.Finding {
	finding := baseFinding(
		"ENV-001",
		"Ограничение программной среды",
		"Ограничение программной среды",
		model.SeverityCritical,
		"Пункты 15.1-15.2 приказа №64 требуют выявления и блокирования неразрешенного программного обеспечения, а для 4 класса - дополнительных ограничений на код и память.",
		"Отсутствие контроля программной среды повышает риск загрузки неразрешенного или модифицированного кода в адресное пространство СУБД.",
		"Подтвердите параметры allowlist_enabled, block_untrusted_code_load и для 4 класса db_user_create_procedures_restricted, memory_wx_exclusive, block_modified_code_load.",
	)

	var evidence []string
	fail := false

	baseChecks := []struct {
		param string
		text  string
	}{
		{"allowlist_enabled", "Не подтвержден перечень разрешенного ПО."},
		{"block_untrusted_code_load", "Не подтверждено блокирование загрузки ПО, не включенного в разрешенный перечень."},
	}
	for _, check := range baseChecks {
		value, ok := config.BoolParam(check.param)
		if !ok {
			evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
			continue
		}
		if !value {
			fail = true
			evidence = append(evidence, check.text)
		}
	}

	if profile.RequireCodeRestrictions {
		extraChecks := []struct {
			param string
			text  string
		}{
			{"db_user_create_procedures_restricted", "Не подтвержден запрет пользователям базы данных создавать хранимые процедуры."},
			{"memory_wx_exclusive", "Не подтверждено размещение кода СУБД в памяти, не доступной одновременно для записи и исполнения."},
			{"block_modified_code_load", "Не подтверждено блокирование загрузки ПО с нарушенной целостностью."},
		}
		for _, check := range extraChecks {
			value, ok := config.BoolParam(check.param)
			if !ok {
				evidence = append(evidence, fmt.Sprintf("%s Ожидается параметр %s.", check.text, check.param))
				continue
			}
			if !value {
				fail = true
				evidence = append(evidence, check.text)
			}
		}
	}

	if len(evidence) == 0 {
		finding.Status = model.StatusPass
		finding.Evidence = []string{"Подтверждены требования по ограничению программной среды и загрузке только разрешенного кода."}
		return finding
	}

	if fail {
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
