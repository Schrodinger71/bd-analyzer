package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bd-scan/internal/model"
)

type Request struct {
	Target         string
	Host           string
	Port           int
	Database       string
	User           string
	Password       string
	SSLMode        string
	PostgreSQLConf string
	HBAConf        string
	IdentConf      string
	MetadataJSON   string
}

func Collect(req Request) (model.ConfigSnapshot, error) {
	snapshot := model.ConfigSnapshot{
		Target:     req.Target,
		Connection: buildConnectionInfo(req),
		Sources: model.SourcePaths{
			PostgreSQLConf: req.PostgreSQLConf,
			HBAConf:        req.HBAConf,
			IdentConf:      req.IdentConf,
			MetadataJSON:   req.MetadataJSON,
		},
		Parameters: make(map[string]model.ConfigParameter),
	}

	liveSnapshot, hasLiveData, err := maybeCollectLive(req)
	if err != nil {
		return snapshot, err
	}

	if snapshot.Target == "" {
		if hasLiveData && liveSnapshot.Target != "" {
			snapshot.Target = liveSnapshot.Target
		} else if req.Database != "" {
			snapshot.Target = req.Database
		} else {
			snapshot.Target = "PostgreSQL target"
		}
	}

	if snapshot.Sources.PostgreSQLConf == "" {
		snapshot.Sources.PostgreSQLConf = liveSnapshot.Sources.PostgreSQLConf
	}
	if snapshot.Sources.HBAConf == "" {
		snapshot.Sources.HBAConf = liveSnapshot.Sources.HBAConf
	}
	if snapshot.Sources.IdentConf == "" {
		snapshot.Sources.IdentConf = liveSnapshot.Sources.IdentConf
	}

	if snapshot.Sources.PostgreSQLConf != "" {
		content, err := os.ReadFile(snapshot.Sources.PostgreSQLConf)
		if err != nil {
			if req.PostgreSQLConf != "" {
				return snapshot, fmt.Errorf("не удалось прочитать postgresql.conf: %w", err)
			}
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось прочитать postgresql.conf по пути %q: %v", snapshot.Sources.PostgreSQLConf, err))
		} else {
			params, warnings := parsePostgreSQLConf(string(content), snapshot.Sources.PostgreSQLConf)
			for key, value := range params {
				snapshot.Parameters[key] = value
			}
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, warnings...)

			baseDir := filepath.Dir(snapshot.Sources.PostgreSQLConf)
			if snapshot.Sources.HBAConf == "" {
				if param, ok := snapshot.Parameters["hba_file"]; ok && strings.TrimSpace(param.Value) != "" {
					snapshot.Sources.HBAConf = normalizePath(baseDir, param.Value)
				} else {
					snapshot.Sources.HBAConf = filepath.Join(baseDir, "pg_hba.conf")
				}
			}

			if snapshot.Sources.IdentConf == "" {
				if param, ok := snapshot.Parameters["ident_file"]; ok && strings.TrimSpace(param.Value) != "" {
					snapshot.Sources.IdentConf = normalizePath(baseDir, param.Value)
				} else {
					snapshot.Sources.IdentConf = filepath.Join(baseDir, "pg_ident.conf")
				}
			}
		}
	}

	if snapshot.Sources.HBAConf != "" {
		content, err := os.ReadFile(snapshot.Sources.HBAConf)
		if err != nil {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось прочитать pg_hba.conf: %v", err))
		} else {
			rules, warnings := parseHBAConf(string(content))
			snapshot.HBARules = rules
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, warnings...)
		}
	}

	if snapshot.Sources.IdentConf != "" {
		content, err := os.ReadFile(snapshot.Sources.IdentConf)
		if err != nil {
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, fmt.Sprintf("не удалось прочитать pg_ident.conf: %v", err))
		} else {
			maps, warnings := parseIdentConf(string(content))
			snapshot.IdentMaps = maps
			snapshot.CollectionWarnings = append(snapshot.CollectionWarnings, warnings...)
		}
	}

	if hasLiveData {
		mergeLiveSnapshot(&snapshot, liveSnapshot)
	}

	if req.MetadataJSON != "" {
		metadata, err := readMetadata(req.MetadataJSON)
		if err != nil {
			return snapshot, fmt.Errorf("не удалось прочитать metadata JSON: %w", err)
		}

		for key, value := range metadata.Settings {
			normalizedKey := strings.ToLower(strings.TrimSpace(key))
			snapshot.Parameters[normalizedKey] = model.ConfigParameter{
				Name:   normalizedKey,
				Value:  strings.TrimSpace(value),
				Source: "metadata",
			}
		}

		snapshot.Roles = metadata.Roles
		snapshot.Audit = metadata.Audit
		snapshot.Backup = metadata.Backup
		snapshot.Integrity = metadata.Integrity
		snapshot.Notes = metadata.Notes
	}

	if len(snapshot.Parameters) == 0 && len(snapshot.HBARules) == 0 && len(snapshot.Roles) == 0 {
		return snapshot, fmt.Errorf("не удалось собрать данные для анализа: укажите хотя бы один доступный источник конфигурации")
	}

	return snapshot, nil
}

func normalizePath(baseDir, value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(baseDir, value)
}

func readMetadata(path string) (model.Metadata, error) {
	var metadata model.Metadata

	data, err := os.ReadFile(path)
	if err != nil {
		return metadata, err
	}

	if err := json.Unmarshal(data, &metadata); err != nil {
		return metadata, err
	}

	if metadata.Settings == nil {
		metadata.Settings = make(map[string]string)
	}

	return metadata, nil
}

func parsePostgreSQLConf(content, source string) (map[string]model.ConfigParameter, []string) {
	parameters := make(map[string]model.ConfigParameter)
	var warnings []string

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		line := stripInlineComment(raw)
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" {
			warnings = append(warnings, fmt.Sprintf("postgresql.conf:%d: пустое имя параметра", lineNo))
			continue
		}

		parameters[normalizedKey] = model.ConfigParameter{
			Name:   normalizedKey,
			Value:  strings.TrimSpace(strings.Trim(value, `"'`)),
			Source: source,
		}
	}

	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("ошибка чтения postgresql.conf: %v", err))
	}

	return parameters, warnings
}

func parseHBAConf(content string) ([]model.HBARule, []string) {
	var rules []model.HBARule
	var warnings []string

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		line := stripInlineComment(raw)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			warnings = append(warnings, fmt.Sprintf("pg_hba.conf:%d: недостаточно полей", lineNo))
			continue
		}

		rule := model.HBARule{
			Type:       strings.ToLower(fields[0]),
			Database:   fields[1],
			User:       fields[2],
			SourceLine: lineNo,
			Raw:        line,
		}

		if rule.Type == "local" {
			rule.Method = strings.ToLower(fields[3])
			if len(fields) > 4 {
				rule.Options = fields[4:]
			}
		} else {
			if len(fields) < 5 {
				warnings = append(warnings, fmt.Sprintf("pg_hba.conf:%d: недостаточно полей для сетевого правила", lineNo))
				continue
			}
			rule.Address = fields[3]
			rule.Method = strings.ToLower(fields[4])
			if len(fields) > 5 {
				rule.Options = fields[5:]
			}
		}

		rules = append(rules, rule)
	}

	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("ошибка чтения pg_hba.conf: %v", err))
	}

	return rules, warnings
}

func parseIdentConf(content string) ([]model.IdentMap, []string) {
	var maps []model.IdentMap
	var warnings []string

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		line := stripInlineComment(raw)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			warnings = append(warnings, fmt.Sprintf("pg_ident.conf:%d: недостаточно полей", lineNo))
			continue
		}

		maps = append(maps, model.IdentMap{
			MapName:      fields[0],
			SystemUser:   fields[1],
			DatabaseUser: fields[2],
			SourceLine:   lineNo,
		})
	}

	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Sprintf("ошибка чтения pg_ident.conf: %v", err))
	}

	return maps, warnings
}

func stripInlineComment(value string) string {
	var builder strings.Builder
	inSingleQuotes := false

	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\'' {
			inSingleQuotes = !inSingleQuotes
		}
		if ch == '#' && !inSingleQuotes {
			break
		}
		builder.WriteByte(ch)
	}

	return strings.TrimSpace(builder.String())
}
