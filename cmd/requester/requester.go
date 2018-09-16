package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/icrowley/fake"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
	"wins21.co.kr/sniper/mserver"
)

const (
	AppName = "Analysis requester"
)

type FileEvent struct {
	SessionId string
	Timestamp time.Time
	SensorId  int
	Protocol  int
	SrcIp     string
	SrcPort   int
	DstIp     string
	DstPort   int
	Domain    string
	Url       string
	TransType int
	FileName  string
	FileSize  int64
	Md5       string
}

func main() {
	// 옵션 설정
	var (
		srcDir   = mserver.CmdFlags.String("src", "/tmp/src", "Source directory")
		dstDir   = mserver.CmdFlags.String("dst", "/home/sniper_bps/", "Destination directory")
		sensorId = mserver.CmdFlags.Int("id", 1, "Sensor ID")
	)
	mserver.CmdFlags.Usage = mserver.PrintHelp
	mserver.CmdFlags.Parse(os.Args[1:])

	run(*sensorId, *srcDir, *dstDir)
}

func run(sensorId int, srcDir, dstDir string) error {

	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
	}

	files, err := ioutil.ReadDir(srcDir)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) < 1 {
		return nil
	}

	for _, f := range files {
		e := FileEvent{}
		e.SessionId = "65" + fake.DigitsN(17)
		e.Timestamp = time.Now().Add(time.Duration(fake.Year(1, 3600)) * time.Second * -1)
		e.SensorId = sensorId
		e.Protocol = 6
		e.SrcIp = "10.0.80." + fake.DigitsN(2)
		e.SrcPort = getRandNum(10000, 40000)
		e.DstIp = fake.IPv4()
		e.DstPort = 80
		e.Domain = fake.DomainName()
		e.Url = "/" + fake.Word() + "/" + fake.Word() + "?_=" + fake.DigitsN(9)
		e.TransType = 3
		e.FileName = f.Name()
		e.FileSize = f.Size()
		md5, err := getMd5(filepath.Join(srcDir, f.Name()))
		if err != nil {
			log.Error(err)
			continue
		}
		e.Md5 = md5

		// Copy
		if err := request(e, filepath.Join(srcDir, f.Name()), tempDir, dstDir); err != nil {
			log.Error(err)
		}
	}

	// 6572388157859326616	1530253365	85	0	0	0	0	6	10.0.80.170	62462	13.33.151.48	80	8	8	update2.test.com	/free2/db2/se/3/x64/a.exe	3	a.exe	45056	null	null	a7ddb28fcc120ef87a6ebd71071ab970
	return nil
}

func request(e FileEvent, path, tempDir, dstDir string) error {

	line := fmt.Sprintf("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\t%s\t%d\t%d\t%d\t%s\t%s\t%d\t%s\t%d\t%s\t%s\t%s\n",
		e.SessionId,
		e.Timestamp.Unix(),
		e.SensorId,
		0,
		0,
		0,
		0,
		e.Protocol,
		e.SrcIp,
		e.SrcPort,
		e.DstIp,
		e.DstPort,
		8,
		8,
		e.Domain,
		e.Url,
		e.TransType,
		e.FileName,
		e.FileSize,
		"null",
		"null",
		e.Md5,
	)

	if tempFile, err := ioutil.TempFile("", ""); err != nil {
		return err
	} else {
		if _, err := tempFile.WriteString(line); err != nil {
			return err
		}

		tempFile.Close()
		if copyFile(tempFile.Name(), filepath.Join(dstDir, "http_"+e.SessionId+".dat")); err != nil {
			return err
		}

		if err := copyFile(path, filepath.Join(dstDir, "http_"+e.SessionId)); err != nil {
			return err
		}
		log.Infof("File requested: %s (md5: %s)", e.FileName, e.Md5)
	}
	return nil
}

func getMd5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	from, err := os.Open(src)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		return err
	}
	return nil
}

func getRandNum(from, to int) int {
	return fake.Year(from-1, to)
}
