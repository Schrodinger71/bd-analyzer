package main

import (
	"flag"
	"fmt"
	"os"

	"bd-scan/internal/collector"
	"bd-scan/internal/model"
	"bd-scan/internal/report"
	"bd-scan/internal/service"
)

func main() {
	var (
		target   = flag.String("target", "PostgreSQL target", "Имя анализируемого экземпляра СУБД")
		classRaw = flag.String("class", "6", "Класс защиты (1-6)")
		host     = flag.String("host", "", "Хост PostgreSQL")
		port     = flag.Int("port", 5432, "Порт PostgreSQL")
		dbName   = flag.String("db", "", "Имя базы данных")
		user     = flag.String("user", "", "Пользователь PostgreSQL")
		password = flag.String("password", "", "Пароль пользователя PostgreSQL")
		sslMode  = flag.String("sslmode", "prefer", "Режим SSL: disable, allow, prefer, require, verify-ca, verify-full")
		confPath = flag.String("conf", "", "Путь к postgresql.conf")
		hbaPath  = flag.String("hba", "", "Путь к pg_hba.conf")
		ident    = flag.String("ident", "", "Путь к pg_ident.conf")
		metaPath = flag.String("meta", "", "Путь к metadata JSON")
		format   = flag.String("format", "txt", "Формат отчета: txt, html, json, pdf")
		outPath  = flag.String("out", "", "Путь для сохранения отчета")
	)

	flag.Parse()

	class, err := model.ParseProtectionClass(*classRaw)
	if err != nil {
		exitErr(err)
	}

	outputFormat, err := report.ParseFormat(*format)
	if err != nil {
		exitErr(err)
	}

	svc := service.Service{}
	result, err := svc.Run(service.RunRequest{
		CollectRequest: collector.Request{
			Host:           *host,
			Port:           *port,
			Database:       *dbName,
			User:           *user,
			Password:       *password,
			SSLMode:        *sslMode,
			Target:         *target,
			PostgreSQLConf: *confPath,
			HBAConf:        *hbaPath,
			IdentConf:      *ident,
			MetadataJSON:   *metaPath,
		},
		Class: class,
	})
	if err != nil {
		exitErr(err)
	}

	data, err := svc.ExportRun(result, outputFormat)
	if err != nil {
		exitErr(err)
	}

	if *outPath == "" {
		_, _ = os.Stdout.Write(data)
		return
	}

	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		exitErr(err)
	}

	fmt.Printf("Отчет сохранен: %s\n", *outPath)
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
