package objs

import (
	"time"
)

const (
	RealtimeCalculator     = 1
	SpecificDateCalculator = 2
	DateRangeCalculator    = 3
)

type FileTransLog struct {
	Rdate          time.Time
	SensorId       int
	IppoolSrcGcode int
	IppoolSrcOcode int
	TransType      int
	SrcIp          uint32
	SrcPort        int
	SrcCountry     string
	DstIp          uint32
	DstPort        int
	DstCountry     string
	Domain         string
	Url            string
	Md5            string
	MailSender     string
	MailRecipient  string
	FileName       string
	MalType        int
	FileType       int
	FileSize       int
	FileJudge      int
	Score          int
	Every10min     time.Time
	SrcIpToDstIpMesh      string
	SrcIpToDomainMesh     string
	SrcIpClassToDstIpMesh string
}

type Item struct {
	Key   interface{}
	Count int64
}
type ItemList []Item

type DataMap map[int]map[string]map[interface{}]int64 // Code / Category / Key / Count
type DataRank map[int]map[string]ItemList             // Code / Category / Key / Ranking

func (p ItemList) Len() int           { return len(p) }
func (p ItemList) Less(i, j int) bool { return p[i].Count < p[j].Count }
func (p ItemList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

