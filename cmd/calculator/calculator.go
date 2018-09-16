package main

import (
	"runtime"
	"os"
	"time"
	log "github.com/sirupsen/logrus"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/golibs/secureconfig"
	"wins21.co.kr/sniper/mserver/objs"
	"wins21.co.kr/sniper/mserver/calculator"
)

const (
	AppName    = "APTX Statistics Calculator"
	AppVersion = "5.0.1806.11801"
)

func main() {

	// CPU 설정
	runtime.GOMAXPROCS(2)

	// 옵션 설정
	var (
		version      = mserver.CmdFlags.Bool("version", false, "Version")
		debug        = mserver.CmdFlags.Bool("debug", false, "Debug")
		verbose      = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig    = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		top          = mserver.CmdFlags.Int("top", 5, "Top N")
		interval     = mserver.CmdFlags.Int64("interval", 15000, "Interval(ms)")
		specificDate = mserver.CmdFlags.String("date", "", "Specific date")
		dateRange    = mserver.CmdFlags.String("range", "", "Date range(StartDate,EndDate,MarkDate)")
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
	defer engine.DB.Close()

	// 통계산출 시작
	calType, targetDate := getCalculatorType(*specificDate, *dateRange)
	dur := time.Duration(*interval) * time.Millisecond
	cal := calculator.NewCalculator(engine, *top, dur, calType, targetDate)
	if err := cal.Start(); err != nil {
		log.Fatal(err)
	}

	// 종료 시그널 대기
	if calType == objs.RealtimeCalculator {
		mserver.WaitForSignals(AppName)
	}
}

func getCalculatorType(specificDate, dateRange string) (int, string) {
	if len(specificDate) > 0 { // 특정 날짜에 대한 통계
		return objs.SpecificDateCalculator, specificDate

	} else if len(dateRange) > 0 { // 특정 기간에 대한 통계
		return objs.DateRangeCalculator, dateRange

	} else {
		return objs.RealtimeCalculator, "" // 실시간 통계
	}
}
