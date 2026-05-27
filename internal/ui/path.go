package ui

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"

	"fyne.io/fyne"
)

func normalizeOptionalPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "file://"):
		value = value[7:]
	case strings.HasPrefix(lower, "file:"):
		value = value[5:]
	}

	if runtime.GOOS == "windows" && len(value) >= 3 && value[0] == '/' && value[2] == ':' {
		value = value[1:]
	}

	return filepath.Clean(filepath.FromSlash(value))
}

func pathFromURI(uri fyne.URI) string {
	if uri == nil {
		return ""
	}

	return normalizeOptionalPath(uri.String())
}

func tryPickOpenPath(extensions []string) (string, bool, error) {
	if runtime.GOOS != "windows" {
		return "", false, nil
	}

	script := fmt.Sprintf(`
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Filter = %q
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
	[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
	Write-Output $dialog.FileName
}
`, buildWindowsDialogFilter(extensions))

	path, err := runWindowsDialog(script)
	return normalizeOptionalPath(path), true, err
}

func tryPickSavePath(defaultName, extension string) (string, bool, error) {
	if runtime.GOOS != "windows" {
		return "", false, nil
	}

	normalizedExt := strings.TrimPrefix(strings.TrimSpace(extension), ".")
	if normalizedExt == "" {
		normalizedExt = "txt"
	}

	script := fmt.Sprintf(`
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.SaveFileDialog
$dialog.Filter = %q
$dialog.DefaultExt = %q
$dialog.AddExtension = $true
$dialog.OverwritePrompt = $true
$dialog.FileName = %q
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
	[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
	Write-Output $dialog.FileName
}
`, buildWindowsDialogFilter([]string{"." + normalizedExt}), normalizedExt, defaultName)

	path, err := runWindowsDialog(script)
	return normalizeOptionalPath(path), true, err
}

func buildWindowsDialogFilter(extensions []string) string {
	cleaned := make([]string, 0, len(extensions))
	patterns := make([]string, 0, len(extensions))
	for _, ext := range extensions {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		ext = strings.ToLower(ext)
		cleaned = append(cleaned, "*"+ext)
		patterns = append(patterns, ext)
	}
	if len(cleaned) == 0 {
		return "All files (*.*)|*.*"
	}
	return fmt.Sprintf("Supported files (%s)|%s|All files (*.*)|*.*", strings.Join(patterns, ", "), strings.Join(cleaned, ";"))
}

func runWindowsDialog(script string) (string, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-STA",
		"-EncodedCommand",
		encodePowerShellScript(script),
	)

	output, err := cmd.Output()
	if err != nil {
		message := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			message = strings.TrimSpace(string(exitErr.Stderr))
		}
		if message == "" {
			message = strings.TrimSpace(string(output))
		}
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("не удалось открыть системный диалог Windows: %s", message)
	}

	return lastNonEmptyLine(string(output)), nil
}

func encodePowerShellScript(script string) string {
	encoded := utf16.Encode([]rune(script))
	bytes := make([]byte, 0, len(encoded)*2)
	for _, r := range encoded {
		bytes = append(bytes, byte(r), byte(r>>8))
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func lastNonEmptyLine(value string) string {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}
