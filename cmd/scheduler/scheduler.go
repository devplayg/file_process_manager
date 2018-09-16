package main

import (
	"github.com/jasonlvhit/gocron"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"path/filepath"
	"wins21.co.kr/sniper/mserver"
	"time"
)

const (
	AppName    = "APTX Scheduler"
	AppVersion = "5.0.1806.11801"
)

var scheduerDir = "/home1/sniper/script/schedule"

func main() {

	var (
		version = mserver.CmdFlags.Bool("version", false, "Version")
		debug   = mserver.CmdFlags.Bool("debug", false, "Debug")
		verbose = mserver.CmdFlags.Bool("v", false, "Verbose")
	)
	mserver.CmdFlags.Usage = mserver.PrintHelp
	mserver.CmdFlags.Parse(os.Args[1:])

	// 버전 출력
	if *version {
		mserver.DisplayVersion(AppName, AppVersion)
		return
	}

	// 엔진 설정
	mserver.NewEngine(AppName, *debug, *verbose)

	gocron.Every(1).Minute().Do(task, "every_minute.sh")
	gocron.Every(1).Hour().Do(task, "every_hour.sh")
	gocron.Every(1).Day().At("00:00").Do(task, "every_day.sh")
	gocron.Every(1).Monday().At("00:00").Do(task, "every_monday.sh")
	//gocron.Every(1).Days().At("00:30").Do(task, "every_first_day.sh")
	gocron.Every(1).Day().At("00:00").Do(task, "every_month.sh")
	go func() {
		<-gocron.Start()
	}()

	mserver.WaitForSignals(AppName)
}

func task(cmd string) {
	if cmd == "every_month.sh" {
		if time.Now().Day() != 1 {
			return
		}
	}

	path := filepath.Join(scheduerDir, cmd)
	log.Debugf("cmd: %s", path)
	_, err := exec.Command("sh", "-c", path).Output()
	if err != nil {
		log.WithFields(log.Fields{
			"cmd": cmd,
		}).Error(err)
	}
}
