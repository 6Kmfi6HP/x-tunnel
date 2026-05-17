package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func SetBuildInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
}

func Main() {
	os.Exit(RunCLI(context.Background()))
}

func RunCLI(parent context.Context) int {
	flag.Parse()

	if showVersion {
		fmt.Println(versionString())
		return 0
	}
	if checkConfigFile != "" || formatConfigFile != "" {
		return runOfflineConfigCommand()
	}
	if configFile == "" && listenAddr == "" {
		flag.Usage()
		return 0
	}
	runtimeConfig, err := LoadConfig(configFile, CLIOverrides(visitedFlags()))
	if err != nil {
		log.Printf("[配置] %v", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine, err := NewEngine(runtimeConfig, RuntimeOptions{
		Build:            BuildInfo{Version: buildVersion, Commit: buildCommit, Date: buildDate},
		ControlAddr:      controlAddr,
		ReadyFile:        readyFile,
		ControlTokenFile: controlTokenFile,
	})
	if err != nil {
		log.Printf("[配置] %v", err)
		return 2
	}
	if err := engine.Start(ctx); err != nil {
		log.Printf("[启动] %v", err)
		if strings.Contains(err.Error(), "listen.bind_failed") {
			return 3
		}
		return 2
	}
	if err := engine.Wait(); err != nil {
		log.Printf("[运行] %v", err)
		return 4
	}
	return 0
}

func runOfflineConfigCommand() int {
	if checkConfigFile != "" && formatConfigFile != "" {
		log.Printf("[配置] -check-config 和 -format-config 不能同时使用")
		return 2
	}
	path := checkConfigFile
	format := false
	if formatConfigFile != "" {
		path = formatConfigFile
		format = true
	}
	raw, err := readConfigCommandInput(path)
	if err != nil {
		log.Printf("[配置] %v", err)
		return 2
	}
	if format {
		formatted, err := FormatConfigJSON(raw)
		if err != nil {
			log.Printf("[配置] %v", err)
			return 2
		}
		if _, err := os.Stdout.Write(formatted); err != nil {
			log.Printf("[配置] 写入 stdout 失败: %v", err)
			return 2
		}
		return 0
	}
	if err := CheckConfigJSON(raw); err != nil {
		log.Printf("[配置] %v", err)
		return 2
	}
	fmt.Println(`{"ok":true}`)
	return 0
}

func readConfigCommandInput(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("配置文件路径不能为空")
	}
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
	return os.ReadFile(path)
}
