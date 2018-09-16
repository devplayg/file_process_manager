package main

import (
	"github.com/jasonlvhit/gocron"
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"wins21.co.kr/sniper/golibs/secureconfig"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/agentcollector"
)

const (
	AppName    = "APTX Agent Classifier"
	AppVersion = "1.0.1806.10101"
)

func main() {
	// CPU 설정
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 옵션 설정
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		debug     = mserver.CmdFlags.Bool("debug", false, "Debug")
		verbose   = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		archiveDir = mserver.CmdFlags.String("archivedir", "/home/sniper_bps/agent", "Archive directory")
		lastSeconds = mserver.CmdFlags.Uint("sec", 600, "Agents who accessed in the last N minutes")
		batchSize = mserver.CmdFlags.Uint("batchsize", 1000, "Batch size")
		//interval  = mserver.CmdFlags.Uint64("interval", 10, "Directory lookup interval(sec)")
	)
	mserver.CmdFlags.Usage = mserver.PrintHelp
	mserver.CmdFlags.Parse(os.Args[1:])

	// 버전 출력
	if *version {
		mserver.DisplayVersion(AppName, AppVersion)
		return
	}

	// 엔진 설정
	engine := mserver.NewEngine(AppName, *debug, *verbose)
	if *setConfig {
		secureconfig.SetConfig(
			engine.ConfigPath,
			"db.hostname, db.port, db.username, db.password, db.database",
			mserver.GetEncryptionKey(),
		)
		return
	}

	// 엔진 시작
	if err := engine.Start(); err != nil {
		log.Fatal(err)
	}
	log.Debug(engine.Config)

	// 데이터베이스 연결
	if err := engine.InitDatabase(2, 2,); err != nil {
		log.Fatal(err)
	}

	// 데이터 분류 시작
	collector  := agentcollector.NewCollector(engine, *lastSeconds, *archiveDir, *batchSize)
	
	// 에이전트 상태정보 수집
	gocron.Every(5).Seconds().Do(collector.ProcessStatus)
	
	// 에이전트 탐지로그 입력
	gocron.Every(5).Seconds().Do(collector.ProcessLogs)
	
	go func() {
		<-gocron.Start()
	}()

	// 종료 시그널 대기
	mserver.WaitForSignals(AppName)
}
