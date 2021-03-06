package mserver

import (
	"crypto/sha256"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"wins21.co.kr/sniper/golibs/secureconfig"
)

const (
	DateDefault = "2006-01-02 15:04:05"
)

var (
	CmdFlags *flag.FlagSet
	encKey   []byte
)

func init() {
	CmdFlags = flag.NewFlagSet("", flag.ExitOnError)
	key := sha256.Sum256([]byte("D?83F4 E?E"))
	encKey = key[:]
}

type Engine struct {
	ConfigPath  string
	Config      map[string]string
	appName     string
	debug       bool
	cpuCount    int
	processName string
	ProcessDir  string
	logOutput   int // 0: STDOUT, 1: File
	LogPrefix   string
	DB          *sql.DB
}

func NewEngine(appName string, debug bool, verbose bool) *Engine {
	e := Engine{
		appName:     appName,
		processName: GetProcessName(),
		debug:       debug,
	}
	e.LogPrefix = "[" + e.processName + "] "
	abs, _ := filepath.Abs(os.Args[0])
	e.ProcessDir = filepath.Dir(abs)
	e.ConfigPath = filepath.Join(e.ProcessDir, "conf", "config.enc")
	e.initLogger(verbose)
	return &e
}

func (e *Engine) IsDebug() bool {
	return e.debug
}

func (e *Engine) checkSubDir(subDir string) error {
	dir := filepath.Join(e.ProcessDir, subDir)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) Start() error {
	var err error

	// 필수 디렉토리 생성
	if err := e.checkSubDir("conf"); err != nil {
		return err
	}
	if err := e.checkSubDir("data"); err != nil {
		return err
	}
	if err := e.checkSubDir("logs"); err != nil {
		return err
	}
	if err := e.checkSubDir("tmp"); err != nil {
		return err
	}
	if err := e.checkSubDir("error"); err != nil {
		return err
	}

	// 설정파일 읽기
	e.Config, err = secureconfig.GetConfig(e.ConfigPath, GetEncryptionKey())
	if err != nil {
		return err
	}
	log.Infof("%s started", e.appName)
	return nil
}

func (e *Engine) StartQuietly() error {
	var err error

	// 필수 디렉토리 생성
	if err := e.checkSubDir("conf"); err != nil {
		return err
	}
	if err := e.checkSubDir("data"); err != nil {
		return err
	}
	if err := e.checkSubDir("logs"); err != nil {
		return err
	}
	if err := e.checkSubDir("tmp"); err != nil {
		return err
	}
	if err := e.checkSubDir("error"); err != nil {
		return err
	}

	// 설정파일 읽기
	e.Config, err = secureconfig.GetConfig(e.ConfigPath, GetEncryptionKey())
	if err != nil {
		return err
	}
	return nil
}

func (e *Engine) Stop() error {
	if e.DB != nil {
		if err := e.DB.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) initLogger(verbose bool) error {
	// Set log format
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		DisableColors: true,
	})

	// Set log level
	if e.debug {
		log.SetLevel(log.DebugLevel)
	}

	if verbose {
		e.logOutput = 0
		log.SetOutput(os.Stdout)
		//orm.DebugLog = orm.NewLog(os.Stdout)
	} else {
		var logFile string
		if e.debug {
			logFile = filepath.Join(e.ProcessDir, "logs", e.processName+"-debug.log")
			//os.Remove(logFile)

		} else {
			logFile = filepath.Join(e.ProcessDir, "logs", e.processName+".log")
		}

		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err == nil {
			log.SetOutput(file)
			e.logOutput = 1
		} else {
			e.logOutput = 0
			log.SetOutput(os.Stdout)
		}
	}

	if log.GetLevel() != log.InfoLevel {
		log.Infof("LoggingLevel=%s", log.GetLevel())
	}

	return nil
}

func (e *Engine) InitDatabase(idleConns, openConns int) error {
	connStr := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?allowAllFiles=true&charset=utf8&parseTime=true&loc=%s",
		e.Config["db.username"],
		e.Config["db.password"],
		e.Config["db.hostname"],
		e.Config["db.port"],
		e.Config["db.database"],
		"Asia%2FSeoul")
	log.Debugf("[db] hostname=%s, username=%s, port=%s, database=%s", e.Config["db.hostname"], e.Config["db.username"], e.Config["db.port"], e.Config["db.database"])

	db, _ := sql.Open("mysql", connStr)
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	db.SetMaxIdleConns(idleConns)
	db.SetMaxOpenConns(openConns)
	e.DB = db
	return nil
}

func (e *Engine) UpdateConfig(section, keyword, value string) error {
	query := `
		insert into sys_config(section, keyword, value, udate)
		values(?, ?, ?, now())
		on duplicate key update
			value = values(value),
			udate = values(udate)
	`
	_, err := e.DB.Exec(query, section, keyword, value)
	if err != nil {
		return err
	}
	return nil
}

func WaitForSignals(appName string) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signalCh:
		log.Infof("%s stopped", appName)

	}
}

func PrintHelp() {
	fmt.Println(strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])))
	CmdFlags.PrintDefaults()
}

func DisplayVersion(prodName, version string) {
	fmt.Printf("%s, v%s\n", prodName, version)
}

func GetProcessName() string {
	return strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0]))
}

func GetEncryptionKey() []byte {
	return encKey
}
