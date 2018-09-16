package objs

import (
	"time"
)

const (
	HTTP  = 0x0001
	SMTP  = 0x0002
	POP3  = 0x0003
	FTP   = 0x0004
	MTA   = 0x0005
	USER1 = 0x0009
	USER2 = 0x000a
)

// Log file
type FileEvent struct {
	Info    feInfo    `json:"info"`
	Network feNetwork `json:"network"`
	Mail    feMail    `json:"mail"`
	Files   []feFile  `json:"file"`
}
type feInfo struct {
	Date       string `json:"date"`
	AnalysisId string `json:"analysis_id"`
	Type       int    `json:"type"`
	FileCount  int    `json:"file_cnt"`
	//UrlCount   int    `json:"url_cnt"`
}
type feNetwork struct {
	SessionId  string `json:"session_id"`
	Domain     string `json:"domain"`
	Url        string `json:"url"`
	Protocol   int    `json:"protocol"`
	SrcIp      uint32 `json:"src_ip"`
	SrcPort    int    `json:"src_port"`
	SrcCountry string `json:"src_country"`
	DstIp      uint32 `json:"dst_ip"`
	DstPort    int    `json:"dst_port"`
	DstCountry string `json:"dst_country"`
}
type feMail struct {
	MailId        string `json:"mail_id"`
	SenderName    string `json:"sender_name"`
	SenderAddr    string `json:"sender_addr"`
	RecipientName string `json:"recipient_name"`
	RecipientAddr string `json:"recipient_addr"`
	Subject       string `json:"subject"`
}
type feFile struct {
	FileId         string `json:"file_id"`
	Md5            string `json:"md5"`
	Sha256         string `json:"sha256"`
	Name           string `json:"name"`
	Type           int    `json:"type"`
	Category       int64  `json:"category"`
	Size           int64  `json:"size"`
	Flags          int    `json:"flags"`
	Score          int    `json:"score"`
	MimeType       string `json:"mime_type"`
	CommentDynamic string `json:"comment_dynamic"`
	CommentStatic  string `json:"comment_static"`
}
type LogFile struct {
	Path  string
	Mtime time.Time
}

func NewLogFile(path string, mtime time.Time) *LogFile {
	return &LogFile{path, mtime}
}

func NewFeFile() feFile {
	return feFile{}
}

type LogFileList []*LogFile

func (a LogFileList) Len() int           { return len(a) }
func (a LogFileList) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a LogFileList) Less(i, j int) bool { return a[i].Mtime.Before(a[j].Mtime) }

// Database
type LogFileTrans struct {
	Rdate          time.Time
	IsSeed         int
	Id             string
	Gid            string
	TransType      int
	SessionId      string
	SensorId       int
	IppoolSrcGcode int
	IppoolSrcOcode int
	IppoolDstGcode int
	IppoolDstOcode int
	Md5            string
	Sha256         string
	SrcIp          uint32
	//SrcIpInt       uint32
	SrcPort    int
	SrcCountry string
	DstIp      uint32
	//DstIpInt       uint32
	DstPort        int
	DstCountry     string
	Domain         string
	Url            string
	Filename       string
	MailSender     string
	MailSenderName string
	MailRcpt       string
	MailRcptName   string
	MalType        int64
	FileType       int
	Score          int
	Size           int64
	MimeType       string
	SensorFlags    int
	ManagerFlags   int
	GroupCount     int
	Gdate          time.Time
	CommentDynamic string
	CommentStatic  string
}

type FileResult struct {
	Md5            string
	Sha256         string
	MalType        int
	FileType       int
	Score          int
	Size           int64
	Flags          int
	Rdate          time.Time
	Udate          time.Time
	CommentDynamic string
	CommentStatic  string
}

type Resource struct {
	Date           time.Time
	CpuUsage       float64
	MemTotal       uint64
	MemUsed        uint64
	HomeHddBlock   uint64
	HomeHddUsed    uint64
	BackupHddBlock uint64
	BackupHddUsed  uint64
	NicSegment     int
	NicPortCount   int
	NicLineStatus  int
	NicLinkStatus  int
}

/*
{
	"info": {
		"type": 1,
		"analysis_id": "1_1_1529542803_24691_0",
		"file_cnt": 1,
		"date": "2018-06-18 12:34:56"
	},
	"mail": {
		"sender_addr": "",
		"sender_name": "",
		"recipient_addr": "",
		"mail_id": "",
		"recipient_name": "",
		"subject": ""
	},
	"network": {
		"session_id": "6569336286653588559",
		"domain": "su5.ahnlab.com",
		"url": "/oes/00/onetouch/switch3/delta.uic",
		"protocol": 6,
		"src_country": "",
		"dst_country": "KR",
		"src_ip": 167784961,
		"dst_ip": 3064110359,
		"src_port": 80,
		"dst_port": 80
	},
	"file": [
		{
			"file_id": "1_1_1529542803_24691_1",
			"sha256": "cb262f14bbb5cf53145.......278fbbf7cf",
			"md5": "ffc33965cf50e0af228dd63aee411944",
			"name": "delta.uic",
			"type": 56,
			"category": 0,
			"mime_type": "application/x-bzip2",
			"comment_static": "",
			"comment_dynamic": "",
			"size": 909,
			"flags": 0,
			"score": 0
		}
	]
}
*/
