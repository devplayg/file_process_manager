package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"
	"wins21.co.kr/sniper/golibs/secureconfig"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/resmanager"
)

const (
	AppName    = "Resource manager"
	AppVersion = "1.0.1806.10101"
)

func main() {
	// CPU 설정
	runtime.GOMAXPROCS(1)

	// 옵션 설정
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		debug     = mserver.CmdFlags.Bool("debug", false, "Debug")
		verbose   = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		watchDir = mserver.CmdFlags.String("datadir", "/home1", "Directory to monitor")
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
	if err := engine.StartQuietly(); err != nil {
		log.Fatal(err)
	}
	defer engine.Stop()

	// 데이터베이스 연결
	if err := engine.InitDatabase(1, 1); err != nil {
		log.Fatal(err)
	}

	// 데이터 분류 시작
	manager := resmanager.NewResManager(engine, *watchDir)
	manager.Start()
}
