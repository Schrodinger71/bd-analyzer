package service

import (
	"bd-scan/internal/analyzer"
	"bd-scan/internal/collector"
	"bd-scan/internal/model"
	"bd-scan/internal/normalize"
	"bd-scan/internal/report"
	"fmt"
	"log"
	"time"
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

const DefaultLiveRunTimeout = 30 * time.Second

func (s Service) Run(req RunRequest) (RunResult, error) {
	if req.CollectRequest.UsesLiveConnection() {
		return s.runWithTimeout(req, DefaultLiveRunTimeout)
	}
	return s.run(req)
}

func (s Service) run(req RunRequest) (RunResult, error) {
	log.Printf("service: run started (live=%t, class=%s, target=%q)", req.CollectRequest.UsesLiveConnection(), req.Class.Label(), req.CollectRequest.Target)

	log.Printf("service: collect started")
	snapshot, err := collector.CollectWithTimeout(req.CollectRequest, collector.DefaultLiveCollectionTimeout)
	if err != nil {
		log.Printf("service: collect failed: %v", err)
		return RunResult{}, err
	}
	log.Printf("service: collect finished (params=%d, hba=%d, roles=%d)", len(snapshot.Parameters), len(snapshot.HBARules), len(snapshot.Roles))

	log.Printf("service: normalize started")
	normalized := normalize.Build(snapshot)
	log.Printf("service: normalize finished")

	log.Printf("service: analyze started")
	analysis := s.analyzer.Analyze(normalized, req.Class)
	log.Printf("service: analyze finished (score=%d)", analysis.Score)

	result := RunResult{
		Snapshot:   snapshot,
		Normalized: normalized,
		Analysis:   analysis,
	}
	log.Printf("service: run returning")
	return result, nil
}

func (s Service) runWithTimeout(req RunRequest, timeout time.Duration) (RunResult, error) {
	type result struct {
		value RunResult
		err   error
	}

	done := make(chan result, 1)
	go func() {
		value, err := s.run(req)
		done <- result{value: value, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-done:
		log.Printf("service: run completed before timeout")
		return res.value, res.err
	case <-timer.C:
		return RunResult{}, fmt.Errorf("анализ живой PostgreSQL превысил лимит ожидания %s", timeout.Round(time.Second))
	}
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
