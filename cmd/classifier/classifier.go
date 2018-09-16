package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"time"
	"wins21.co.kr/sniper/golibs/secureconfig"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/classifier"
)

const (
	AppName    = "APTX Classifier"
	AppVersion = "1.0.1807.10501"
)

func main() {
	// CPU 설정
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 옵션 설정
	var (
		version        = mserver.CmdFlags.Bool("version", false, "Version")
		debug          = mserver.CmdFlags.Bool("debug", false, "Debug")
		verbose        = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig      = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		batchSize      = mserver.CmdFlags.Uint("batchsize", 5000, "Batch size")
		archiveDir     = mserver.CmdFlags.String("dir", "/home1/aptx/data", "Data directory")
		fileStorageDir = mserver.CmdFlags.String("storage", "/home1/sniper/md5", "File storage")
		interval       = mserver.CmdFlags.Duration("interval", 2000*time.Millisecond, "Interval")
		retry          = mserver.CmdFlags.String("retry", "", "Retry target directory or file")
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
	if err := engine.InitDatabase(2, 2); err != nil {
		log.Fatal(err)
	}
	defer engine.Stop()

	// 데이터 분류 시작
	clf, err := classifier.NewClassifier(engine, *archiveDir, *fileStorageDir, *batchSize, *interval)
	if err != nil {
		log.Fatal(err)
	}

	// 시작
	if len(*retry) > 0 {
		if err := clf.Retry(*retry); err != nil {
			log.Error(err)
		}
	} else {
		if err := clf.Start(); err != nil {
			log.Fatal(err)
		}

		// 종료 시그널 대기
		mserver.WaitForSignals(AppName)
	}
}
