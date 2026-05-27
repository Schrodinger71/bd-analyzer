# bd-analyzer

Программное средство анализа защищенности конфигураций PostgreSQL по формализованным контрольным профилям, построенным по мотивам статьи о проверке соответствия требованиям приказа ФСТЭК России N 64.

Проект включает:

- модуль сбора конфигурации из `postgresql.conf`, `pg_hba.conf`, `pg_ident.conf`;
- модуль нормализации параметров в единую внутреннюю модель;
- модуль анализа с набором правил по аутентификации, доступу, аудиту, резервированию и контролю целостности;
- модуль отчетности с экспортом в `TXT`, `HTML`, `JSON` и `PDF`;
- графический интерфейс на Fyne и CLI для пакетного запуска.

## Быстрый запуск CLI

```powershell
go run .\cmd\app-cli\main.go `
  -target "Контур-1" `
  -class 4 `
  -conf ".\examples\demo\postgresql.conf" `
  -meta ".\examples\demo\metadata.json" `
  -format html `
  -out ".\report.html"
```

Если `-out` не указан, отчет печатается в консоль.

## Metadata JSON

Часть проверок в статье опирается не только на конфигурационные файлы, но и на сведения о ролях, резервном копировании, аудите и механизмах контроля целостности. Для этого проект поддерживает дополнительный `metadata JSON`.

Пример структуры:

```json
{
  "settings": {
    "password_min_length": "12",
    "auth_max_failed_attempts": "5",
    "password_encryption": "scram-sha-256"
  },
  "audit": {
    "enabled": true,
    "provider": "pgaudit",
    "events": ["ddl", "role", "write"],
    "log_directory_protected": true,
    "immutable_storage": false
  },
  "backup": {
    "enabled": true,
    "schedule": "daily",
    "retention_days": 14,
    "encrypted": true,
    "tested_restore": true
  },
  "integrity": {
    "config_control_enabled": true,
    "checksums_enabled": true
  },
  "roles": [
    {
      "name": "postgres",
      "login": true,
      "superuser": true,
      "inherit": true
    }
  ]
}
```

## Демонстрационный набор

В каталоге `examples/demo` лежит готовый комплект файлов:

- `postgresql.conf`
- `pg_hba.conf`
- `pg_ident.conf`
- `metadata.json`

Проверка демо-профиля:

```powershell
go run .\cmd\app-cli\main.go -target demo -class 4 -conf .\examples\demo\postgresql.conf -meta .\examples\demo\metadata.json -format txt
```

## GUI

Основная команда запуска графического интерфейса:

```powershell
go run .
```

Сборка на Windows:

```powershell
fyne package --os windows --name "bd-analyzer" --icon icon.png --app-id com.tulgu.bdscan -release
```

## Важно

Текущие контрольные профили реализуют практическую интерпретацию статьи и подходят как основа для развития базы правил. Для строгого регуляторного аудита под конкретный объект информатизации правила стоит дополнить точной матрицей требований вашей организации.
