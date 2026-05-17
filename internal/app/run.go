package app

import (
	"context"
	"flag"
	"fmt"
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
