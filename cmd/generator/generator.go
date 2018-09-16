package main

import (
	"encoding/json"
	"fmt"
	"github.com/icrowley/fake"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"wins21.co.kr/sniper/golibs/network"
	"wins21.co.kr/sniper/golibs/secureconfig"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/objs"
)

const (
	AppName    = "APTX Data Generator"
	AppVersion = "1.0.1806.10101"
)

type Sensor struct {
	id       int
	ipPrefix string
}

func main() {
	// 옵션 설정
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		count     = mserver.CmdFlags.Int("count", 1, "Event count")
		setConfig = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		dir       = mserver.CmdFlags.String("dir", "data", "Directory path")
		ago       = mserver.CmdFlags.Int("ago", 0, "Past date")
	)
	mserver.CmdFlags.Usage = mserver.PrintHelp
	mserver.CmdFlags.Parse(os.Args[1:])

	// 버전 출력
	if *version {
		mserver.DisplayVersion(AppName, AppVersion)
		return
	}

	// 엔진 설정
	engine := mserver.NewEngine(AppName, true, true)
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
	if err := engine.InitDatabase(1, 1); err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	g := NewGenerator(engine, *count, *dir, *ago)
	g.Start()
	log.Debugf("count=%d, time=%3.1f", *count, time.Since(start).Seconds())
}

type Generator struct {
	engine    *mserver.Engine
	count     int
	sensors   []Sensor
	transType []int
	fileMap   map[string]string
	fileExts  []string
	//malMap    map[int]string
	malTypes  []int64
	fileTypes []int
	flags     []int
	dir       string
	ago       int
}

func NewGenerator(engine *mserver.Engine, count int, dir string, ago int) *Generator {
	return &Generator{
		engine: engine,
		count:  count,
		dir:    dir,
		ago:    ago,
	}
}

func (g *Generator) Start() error {
	g.loadAsset()
	g.generate()

	return nil

}

//
func (g *Generator) loadAsset() error {
	// sensor
	query := "select sensor_id, ip from ast_ippool"
	rows, err := g.engine.DB.Query(query)
	if err != nil {
		log.Error(err)
	}
	defer rows.Close()

	for rows.Next() {
		s := Sensor{}
		err := rows.Scan(&s.id, &s.ipPrefix)
		if err != nil {
			return err
		}
		s.ipPrefix = strings.TrimSuffix(s.ipPrefix, ".0")
		g.sensors = append(g.sensors, s)
	}
	g.fileTypes = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 50, 51, 52, 53, 54, 55, 56, 100}
	g.transType = []int{objs.HTTP, objs.FTP, objs.POP3, objs.SMTP, objs.MTA}
	g.fileMap = map[string]string{
		".aac":   "audio/aac",
		".abw":   "application/x-abiword",
		".arc":   "application/octet-stream",
		".avi":   "video/x-msvideo",
		".azw":   "application/vnd.amazon.ebook",
		".bin":   "application/octet-stream",
		".bz":    "application/x-bzip",
		".bz2":   "application/x-bzip2",
		".csh":   "application/x-csh",
		".css":   "text/css",
		".csv":   "text/csv",
		".doc":   "application/msword",
		".epub":  "application/epub+zip",
		".gif":   "image/gif",
		".html":  "text/html",
		".ico":   "image/x-icon",
		".ics":   "text/calendar",
		".jar":   "application/java-archive",
		".jpg":   "image/jpeg",
		".js":    "application/js",
		".json":  "application/json",
		".midi":  "audio/midi",
		".mpeg":  "video/mpeg",
		".mpkg":  "application/vnd.apple.installer+xml",
		".odp":   "application/vnd.oasis.opendocument.presentation",
		".ods":   "application/vnd.oasis.opendocument.spreadsheet",
		".odt":   "application/vnd.oasis.opendocument.text",
		".oga":   "audio/ogg",
		".ogv":   "video/ogg",
		".ogx":   "application/ogg",
		".pdf":   "application/pdf",
		".ppt":   "application/vnd.ms-powerpoint",
		".rar":   "application/x-rar-compressed",
		".rtf":   "application/rtf",
		".sh":    "application/x-sh",
		".svg":   "image/svg+xml",
		".swf":   "application/x-shockwave-flash",
		".tar":   "application/x-tar",
		".tiff":  "image/tiff",
		".ttf":   "application/x-font-ttf",
		".vsd":   "application/vnd.visio",
		".wav":   "audio/x-wav",
		".weba":  "audio/webm",
		".webm":  "video/webm",
		".webp":  "image/webp",
		".woff":  "application/x-font-woff",
		".xhtml": "application/xhtml+xml",
		".xls":   "application/vnd.ms-excel",
		".xml":   "application/xml",
		".xul":   "application/vnd.mozilla.xul+xml",
		".zip":   "application/zip",
		".3gp":   "video/3gpp",
	}

	g.fileExts = make([]string, 0, len(g.fileMap))
	for k := range g.fileMap {
		g.fileExts = append(g.fileExts, k)
	}

	//g.malMap = map[int]string{
	//	1:   "PUP",
	//	2:   "BDR",
	//	3:   "RKIT",
	//	4:   "TR",
	//	5:   "VBS",
	//	6:   "WIN",
	//	7:   "WORM",
	//	8:   "New",
	//	9:   "EXPLOIT",
	//	10:  "URL",
	//	11:  "DYNAMIC",
	//	12:  "ANDROID",
	//	13:  "LINUX",
	//	14:  "SUS",
	//	15:  "RANSOMWARE",
	//	100: "NORMAL",
	//}
	//g.malTypes = make([]int, 0, len(g.malTypes))
	//for k := range g.malMap {
	//	g.malTypes = append(g.malTypes, k)
	//}
	g.malTypes = []int64{0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000, 0x01000000, 0x02000000, 0x04000000}

	g.flags = []int{1, 2, 64, 128, 512, 1024}
	return nil
}

func (g *Generator) generate() error {
	for a := 0; a < g.count; a++ {
		t := time.Now().Add(time.Duration(fake.Year(1, 3600)) * time.Second * -1).Add(time.Duration(g.ago*86400) * time.Second)
		sensor := g.sensors[getRandNum(0, len(g.sensors)-1)]
		transType := g.transType[getRandNum(0, len(g.transType)-1)]
		unixTimestamp := t.UnixNano() / 1000000
		prefixId := fmt.Sprintf("%d_%d_%d_1000_", sensor.id, transType, unixTimestamp)

		e := objs.FileEvent{}
		e.Info.AnalysisId = prefixId + "0"
		e.Info.Type = transType
		e.Info.FileCount = getRandNum(1, 5)
		e.Info.Date = t.Format(mserver.DateDefault)

		//log.Debug(sensor.ipPrefix + strconv.Itoa(getRandNum(2,254)))
		if transType == objs.HTTP || transType == objs.FTP {
			e.Network.SessionId = fake.DigitsN(10)
			e.Network.SrcIp, e.Network.SrcPort, e.Network.SrcCountry = getSrc(sensor)
			e.Network.DstIp, e.Network.DstPort, e.Network.DstCountry = getDst()
			e.Network.Domain = fake.DomainName()
			e.Network.Url = "/" + fake.Word() + "/" + fake.Word() + "?sessid=" + fake.DigitsN(10)
		} else if transType == objs.SMTP || transType == objs.POP3 {
			e.Network.SessionId = fake.DigitsN(10)
			e.Network.SrcIp, e.Network.SrcPort, e.Network.SrcCountry = getSrc(sensor)
			e.Network.DstIp, e.Network.DstPort, e.Network.DstCountry = getDst()
			e.Mail.SenderName = fake.FullName()
			e.Mail.SenderAddr = fake.EmailAddress()
			e.Mail.RecipientName = fake.FullName()
			e.Mail.RecipientAddr = fake.EmailAddress()
			e.Mail.Subject = fake.EmailSubject()
		} else {
			e.Mail.SenderName = fake.FullName()
			e.Mail.SenderAddr = fake.EmailAddress()
			e.Mail.RecipientName = fake.FullName()
			e.Mail.RecipientAddr = fake.EmailAddress()
			e.Mail.Subject = fake.EmailSubject()
		}

		for i := 1; i <= e.Info.FileCount; i++ {
			fileExt := g.fileExts[getRandNum(0, len(g.fileExts)-1)]

			f := objs.NewFeFile()
			f.FileId = prefixId + strconv.Itoa(i)
			f.Md5 = fake.CharactersN(32)
			f.Sha256 = fake.CharactersN(64)
			f.Name = fake.Word() + fileExt
			f.Type = getRandNum(0, len(g.fileTypes)-1)
			f.Category = g.getMalType()
			f.MimeType = g.fileMap[fileExt]
			f.Size = getRand64Num(1000, 1000000)
			f.Score = getRandNum(1, 10) * 10
			f.Flags = g.getFlags()

			e.Files = append(e.Files, f)
		}

		b, _ := json.Marshal(e)

		f, err := ioutil.TempFile(g.dir, "")
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := f.Write(b); err != nil {
			return err
		}

		f.Close()

		os.Rename(f.Name(), f.Name()+".log")
	}
	return nil
}

func (g *Generator) getMalType() int64 {
	n1 := getRandNum(0, len(g.malTypes)-1)
	n2 := getRandNum(0, len(g.malTypes)-1)

	return int64(g.malTypes[n1] | g.malTypes[n2])
}

func (g *Generator) getFlags() int {
	var val int
	for _, n := range g.flags {
		if getRandNum(0, 1) == 1 {
			val |= n
		}
	}
	return val
}

func getSrc(sensor Sensor) (uint32, int, string) {
	str := sensor.ipPrefix + "." + strconv.Itoa(getRandNum(2, 254))
	ip := net.ParseIP(str)
	ipInt := network.IpToInt32(ip)
	port := getRandNum(80, 65535)
	country := "KR"

	return ipInt, port, country
}

func getDst() (uint32, int, string) {
	str := fake.IPv4()
	ip := net.ParseIP(str)
	ipInt := network.IpToInt32(ip)
	port := getRandNum(80, 65535)
	country := "KR"
	return ipInt, port, country
}

//
//
//type FileEvent struct {
//	Info    feInfo    `json:"info"`
//	Network feNetwork `json:"network"`
//	Mail    feMail    `json:"mail"`
//	Files   []feFile  `json:"file"`
//}
//type feInfo struct {
//	AnalysisId string `json:"analysis_id"`
//	Type       int    `json:"type"`
//	FileCount  int    `json:"file_cnt"`
//	UrlCount   int    `json:"url_cnt"`
//}
//type feNetwork struct {
//	SessionId string `json:"session_id"`
//	SrcIp     net.IP `json:"-"`
//	SrcIpStr  string `json:"src_ip"`
//	SrcPort   int    `json:"src_port"`
//	DstIp     net.IP `json:"-"`
//	DstIpStr  string `json:"dst_ip"`
//	DstPort   int    `json:"dst_port"`
//	Protocol  int    `json:"protocol"`
//	Domain    string `json:"d_site"`
//	Url       string `json:"d_path"`
//}
//type feMail struct {
//	MailId        string `json:"mail_id"`
//	SenderName    string `json:"sender_name"`
//	SenderAddr    string `json:"sender_addr"`
//	RecipientName string `json:"recipient_name"`
//	RecipientAddr string `json:"recipient_addr"`
//	Subject       string `json:"subject"`
//}
//type feFile struct {
//	FileId   string `json:"f_id"`
//	Md5      string `json:"md5"`
//	Sha256   string `json:"sha256"`
//	Name     string `json:"name"`
//	TypeDesc string `json:"extern"`
//	Type     int    `json:"extern_code"`
//	Category int    `json:"category"`
//	Content  string `json:"content"`
//	Size     int64  `json:"size"`
//	Score    int    `json:"score"`
//	Date     string `json:"rdate"`
//	Flags    int    `json:"rule_flag"`
//}

func getRandNum(from, to int) int {
	return fake.Year(from-1, to)
}

func getRand64Num(from, to int) int64 {
	return int64(fake.Year(from-1, to))
}
