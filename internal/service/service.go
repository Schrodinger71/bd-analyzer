package service

import (
	"bd-scan/internal/analyzer"
	"bd-scan/internal/collector"
	"bd-scan/internal/model"
	"bd-scan/internal/normalize"
	"bd-scan/internal/report"
)

type RunRequest struct {
	CollectRequest collector.Request
	Class          model.ProtectionClass
}

type RunResult struct {
	Snapshot   model.ConfigSnapshot
	Normalized model.NormalizedConfig
	Analysis   model.AnalysisResult
}

type Service struct {
	analyzer analyzer.Service
}

func (s Service) Run(req RunRequest) (RunResult, error) {
	snapshot, err := collector.Collect(req.CollectRequest)
	if err != nil {
		return RunResult{}, err
	}

	normalized := normalize.Build(snapshot)
	analysis := s.analyzer.Analyze(normalized, req.Class)

	return RunResult{
		Snapshot:   snapshot,
		Normalized: normalized,
		Analysis:   analysis,
	}, nil
}

func (s Service) Export(result model.AnalysisResult, format report.Format) ([]byte, error) {
	return report.Render(result, format)
}

func (s Service) Preview(result model.AnalysisResult) string {
	data, err := report.Render(result, report.FormatText)
	if err != nil {
		return err.Error()
	}
	return string(data)
}
