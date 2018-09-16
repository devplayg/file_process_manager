package calculator

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"wins21.co.kr/sniper/mserver/objs"
)

// ---------------------------------------------------------------------------------------------
type fileEventCalculator struct {
	calculator *Calculator
	wg         *sync.WaitGroup
	dataMap    objs.DataMap
	dataRank   objs.DataRank
	tables     map[string]bool
	from       string
	to         string
	mark       string
	total      int
}

func NewFileEventStats(calculator *Calculator, from, to, mark string) *fileEventCalculator {
	return &fileEventCalculator{
		calculator: calculator,
		dataMap:    make(objs.DataMap),
		dataRank:   make(objs.DataRank),
		tables:     map[string]bool{},
		from:       from,
		to:         to,
		mark:       mark,
	}
}

func (c *fileEventCalculator) Start(wg *sync.WaitGroup) error {
	defer wg.Done()
	start := time.Now()

	// 통계 생성
	if err := c.produceStats(); err != nil {
		log.Error(err)
		return err
	}

	// DB 입력
	if err := c.insert(); err != nil {
		log.Error(err)
		return err
	}
	//time.Sleep(5 * time.Second)
	log.Debugf("stats=%s, rows=%d, time=%3.1fs", "file", c.total, time.Since(start).Seconds())
	return nil
}

func (c *fileEventCalculator) produceStats() error {
	// Initialize
	c.dataMap[RootId] = make(map[string]map[interface{}]int64)
	c.dataRank[RootId] = make(map[string]objs.ItemList)

	query := `
		select 	t.rdate,
				(sensor_id + 100000) sensor_id,
				trans_type,
				ippool_src_gcode,
				ippool_src_ocode,
				ifnull(t.trans_type, 0) trans_type,
				t.md5,
				src_ip,
				src_port,
				src_country,
				dst_ip,
				dst_port,
				dst_country,
				domain,
				concat(domain, url) url,
				ifnull(t1.size, t.file_size) file_size,
				t1.file_type,				
				t1.mal_type,
				t.file_name,								
				mail_sender,
				mail_recipient,
				t1.score,
				case
					when t1.score = 100 then 1
					when t1.score < 100 and t1.score >= 40 then 2
					else 3
				end file_judge,
				concat(inet_ntoa(src_ip), ',', inet_ntoa(dst_ip)) src_ip_to_dst_ip_mesh,
				concat(inet_ntoa(src_ip), ',', domain) src_ip_to_domain_mesh,
				concat(INET_NTOA(INET_ATON( inet_ntoa(src_ip) ) & 4294967040), ',', inet_ntoa(dst_ip)) src_ip_class_to_dst_ip_mesh,
				from_unixtime(unix_timestamp(t.rdate) - (unix_timestamp(t.rdate) % 600)) every10min
		from log_filetrans t left outer join pol_filehash t1 on t1.md5 = t.md5
		where t.rdate between ? and ?
	`
	rows, err := c.calculator.engine.DB.Query(query, c.from, c.to)
	if err != nil {
		log.Error(err)
		return err
	}
	defer rows.Close()

	// 이벤트 맵 생성
	for rows.Next() {
		// 이벤트 객체 생성
		e := objs.FileTransLog{}

		// 데이터 읽기
		err := rows.Scan(
			&e.Rdate,
			&e.SensorId,
			&e.TransType,
			&e.IppoolSrcGcode,
			&e.IppoolSrcOcode,
			&e.TransType,
			&e.Md5,
			&e.SrcIp,
			&e.SrcPort,
			&e.SrcCountry,
			&e.DstIp,
			&e.DstPort,
			&e.DstCountry,
			&e.Domain,
			&e.Url,
			&e.FileSize,
			&e.FileType,
			&e.MalType,
			&e.FileName,
			&e.MailSender,
			&e.MailRecipient,
			&e.Score,
			&e.FileJudge,
			&e.SrcIpToDstIpMesh,
			&e.SrcIpToDomainMesh,
			&e.SrcIpClassToDstIpMesh,
			&e.Every10min,
		)
		if 	err != nil {
			return err
		}

		// 통계 처리
		// "srcip,dstip,md5,dstcountry,dstdomain,dsturi,transtype,filetype,malcategory,filejudge,ipmesh,ipclassmesh"
		c.calStats(&e, "md5", e.Md5, StatsNormal|StatsMalware)
		c.calStats(&e, "transtype", e.TransType, StatsNormal|StatsMalware)
		c.calStats(&e, "filetype", e.FileType, StatsNormal|StatsMalware)
		c.calStats(&e, "malcategory", e.MalType, StatsMalware)
		c.calStats(&e, "filejudge", e.FileJudge, StatsNormal|StatsMalware)
		c.calStats(&e, "ipclassmesh", e.SrcIpClassToDstIpMesh, StatsNormal)
		c.calStats(&e, "ipmesh", e.SrcIpToDstIpMesh, StatsMalware)

		if e.TransType == objs.HTTP || e.TransType == objs.FTP {
			if len(e.DstCountry) > 0 {
				c.calStats(&e, "dstcountry", e.DstCountry, StatsNormal|StatsMalware)
			}
			if len(e.Domain) > 0 {
				c.calStats(&e, "dstdomain", e.Domain, StatsNormal|StatsMalware)
				c.calStats(&e, "ipdomainmesh", e.SrcIpToDomainMesh, StatsNormal|StatsMalware)
			}
			if len(e.Url) > 0 {
				c.calStats(&e, "dsturi", e.Url, StatsNormal|StatsMalware)
			}
		}

		if e.SrcIp > 0 {
			c.calStats(&e, "srcip", e.SrcIp, StatsNormal|StatsMalware)
		}
		if e.DstIp > 0 {
			c.calStats(&e, "dstip", e.DstIp, StatsNormal|StatsMalware)
		}

		c.total++
	}
	err = rows.Err()
	if err != nil {
		log.Error(err)
		return err
	}

	// Determine rankings
	for id, m := range c.dataMap {
		for category, data := range m {
			if strings.HasSuffix(category, "_mal") {
				c.dataRank[id][category] = DetermineRankings(data, 0)
			} else {
				c.dataRank[id][category] = DetermineRankings(data, c.calculator.top)
			}
		}
	}
	return nil
}

func (c *fileEventCalculator) calStats(e *objs.FileTransLog, category string, val interface{}, flags int) error {
	if flags&StatsNormal > 0 {
		c.addToStats(e, category, val)
	}

	if flags&StatsMalware > 0 && e.Score == 100 {
		c.addToStats(e, category+"_mal", val)
	}
	return nil
}

func (c *fileEventCalculator) addToStats(e *objs.FileTransLog, category string, val interface{}) error {

	// By sensor
	if e.SensorId > 0 {
		if _, ok := c.dataMap[e.SensorId]; !ok {
			c.dataMap[e.SensorId] = make(map[string]map[interface{}]int64)
			c.dataRank[e.SensorId] = make(map[string]objs.ItemList)
		}
		if _, ok := c.dataMap[e.SensorId][category]; !ok {
			c.dataMap[e.SensorId][category] = make(map[interface{}]int64)
			c.dataRank[e.SensorId][category] = nil
		}
		c.dataMap[e.SensorId][category][val] += 1
	}

	// By group
	if e.IppoolSrcGcode > 0 {
		if _, ok := c.dataMap[e.IppoolSrcGcode]; !ok {
			c.dataMap[e.IppoolSrcGcode] = make(map[string]map[interface{}]int64)
			c.dataRank[e.IppoolSrcGcode] = make(map[string]objs.ItemList)
		}
		if _, ok := c.dataMap[e.IppoolSrcGcode][category]; !ok {
			c.dataMap[e.IppoolSrcGcode][category] = make(map[interface{}]int64)
			c.dataRank[e.IppoolSrcGcode][category] = nil
		}
		c.dataMap[e.IppoolSrcGcode][category][val] += 1
	}

	// To all
	if _, ok := c.dataMap[RootId][category]; !ok {
		c.dataMap[RootId][category] = make(map[interface{}]int64)
		c.dataRank[RootId][category] = nil
	}
	c.dataMap[RootId][category][val] += 1

	// By member
	if arr, ok := c.calculator.memberAssets[e.IppoolSrcGcode]; ok {
		for _, memberId := range arr {
			id := memberId * -1

			if _, ok := c.dataMap[id]; !ok {
				c.dataMap[id] = make(map[string]map[interface{}]int64)
				c.dataRank[id] = make(map[string]objs.ItemList)
			}
			if _, ok := c.dataMap[id][category]; !ok {
				c.dataMap[id][category] = make(map[interface{}]int64)
				c.dataRank[id][category] = nil
			}
			c.dataMap[id][category][val] += 1
		}
	}

	return nil
}

func (c *fileEventCalculator) insert() error {
	fm := make(map[string]*os.File)
	defer func() {
		for _, file := range fm {
			file.Close()

			if c.calculator.engine.IsDebug() {
				os.Rename(file.Name(), "tmp/"+filepath.Base(file.Name()))
			} else {
				os.Remove(file.Name())
			}
		}
	}()
	for id, m := range c.dataRank {
		for category, list := range m {
			if _, ok := fm[category]; !ok {
				tempFile, err := ioutil.TempFile("data", "stats_"+category+"_")
				if err != nil {
					return err
				}
				fm[category] = tempFile
			}

			for _, item := range list {
				str := fmt.Sprintf("%s\t%d\t%v\t%d\n", c.mark, id, item.Key, item.Count)
				fm[category].WriteString(str)
			}
		}
	}

	//o := orm.NewOrm()
	for category, file := range fm {
		file.Close()
		query := fmt.Sprintf("LOAD DATA LOCAL INFILE %q INTO TABLE stat_%s", file.Name(), category)

		_, err := c.calculator.engine.DB.Exec(query)
		if err == nil {
			//		//num, _ := res.RowsAffected()
			//		//log.Debugf("affectedRows=%d, category=%s", num, category)
		} else {
			return err
		}
	}

	return nil
}
