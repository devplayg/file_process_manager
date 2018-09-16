package calculator

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/objs"
)

const (
	RootId = -1
)

const (
	StatsNormal = 1 + iota
	StatsMalware
)

const (
	FileEventStats = iota + 1
	NetworkEventStats
	AgentEventStats
)

var StatsDesc = map[int]string{
	FileEventStats:    "file",
	NetworkEventStats: "network",
	AgentEventStats:   "agent",
}

type Calculator struct {
	engine             *mserver.Engine // 엔진
	top                int             // Top N 순위
	interval           time.Duration   // 실행 주기(실시간 모드에서 사용)
	calType            int             // 산출기 타입(실시간, 특정날짜, 특정기간)
	targetDate         string          // 대상 날짜
	memberAssets       map[int][]int   // 사용자 자산
	fileStatsTables    []string        // 이벤트 통계 테이블
	networkStatsTables []string        // 상태 통계 테이블
	agentStatsTables   []string        // 상태 통계 테이블
	tmpDir             string          // 임시 디렉토리
	eventRank          objs.DataRank
}

func NewCalculator(engine *mserver.Engine, top int, interval time.Duration, calType int, targetDate string) *Calculator {
	return &Calculator{
		engine:     engine,
		top:        top,
		interval:   interval,
		calType:    calType,
		targetDate: targetDate,
		tmpDir:     filepath.Join(engine.ProcessDir, "tmp"),
		fileStatsTables: []string{
			"md5", "transtype", "filetype", "malcategory", "filejudge",
			"srcip", "dstip", "srcip", "dstip",
			"dstcountry", "dstdomain", "dsturi",
			"ipmesh", "ipclassmesh", "ipdomainmesh",
		},
		networkStatsTables: []string{},
		agentStatsTables:   []string{},
	}
}

// 이젠 통계 삭제
func (c *Calculator) removeStats(date string, isToday bool) error {
	query := "delete from stat_%s where rdate >= ? and rdate <= ?"
	if isToday {
		query += " and rdate <> (select value from sys_config where section = 'stats' and keyword = 'last_updated')"
	}
	from := date + " 00:00:00"
	to := date + " 23:59:59"

	for _, k := range append(c.fileStatsTables, append(c.networkStatsTables, c.agentStatsTables...)...) {
		_, err := c.engine.DB.Exec(fmt.Sprintf(query, k), from, to)
		if err != nil {
			log.Error(err)
			return err
		}
		_, err = c.engine.DB.Exec(fmt.Sprintf(query, k+"_mal"), from, to)
		if err != nil {
			log.Error(err)
			return err
		}
	}

	return nil
}

//
//func (c *Calculator) createTables() error {
//	query := `
//		CREATE TABLE IF NOT EXISTS stats_%s (
//			date      datetime NOT NULL,
//			asset_id  int(11) NOT NULL,
//			item      varchar(64) NOT NULL,
//			count     int(10) unsigned NOT NULL,
//			rank      int(10) unsigned NOT NULL,
//			KEY       ix_date (date),
//			KEY       ix_assetid (date, asset_id)
//		) ENGINE=InnoDB DEFAULT CHARSET=utf8;
//	`
//	for _, k := range append(c.eventTableKeys, c.extraTableKeys...) {
//		_, err := c.engine.DB.Exec(fmt.Sprintf(query, k))
//		if err != nil {
//			return err
//		}
//	}
//	return nil
//}

func (c *Calculator) Start() error {
	//if err := c.createTables(); err != nil {
	//	log.Fatal(err)
	//}

	if c.calType == objs.SpecificDateCalculator {
		t, err := time.Parse("2006-01-02", c.targetDate)
		if err != nil {
			return err
		}

		// 기존 통계 삭제
		if err := c.removeStats(t.Format("2006-01-02"), false); err != nil {
			log.Error(err)
			return err
		}

		// 통계 산출
		if err := c.calculate(
			t.Format("2006-01-02")+" 00:00:00",
			t.Format("2006-01-02")+" 23:59:59",
			t.Format("2006-01-02")+" 00:00:00",
		); err != nil {
			log.Error(err)
			return err
		}
	} else if c.calType == objs.DateRangeCalculator {
		// 추후 보고서에서 사용

	} else if c.calType == objs.RealtimeCalculator { // 실시간 통계(당일)
		go func() {
			log.Debugf("cal_type=%d, interval=%s", c.calType, c.interval.String())
			for {
				t := time.Now()

				// 통계산출
				if err := c.calculate(
					t.Format("2006-01-02")+" 00:00:00",
					t.Format("2006-01-02")+" 23:59:59",
					t.Format(mserver.DateDefault),
				); err == nil {
					// 최종 통계산출 시간 업데이트
					if err := c.engine.UpdateConfig("stats", "last_updated", t.Format(mserver.DateDefault)); err == nil {
						// 직전에 산출한 통계 삭제
						if err := c.removeStats(t.Format("2006-01-02"), true); err != nil {
							log.Error(err)
						}
					} else {
						log.Error(err)
					}
				} else {
					log.Error(err)
				}
				time.Sleep(c.interval)
			}
		}()
	}

	return nil
}

func (c *Calculator) calculate(from, to, mark string) error {
	var err error

	// 사용자 자산 조회
	c.memberAssets, err = c.getMemberAssets()
	if err != nil {
		log.Error(err)
	}

	start := time.Now()
	log.Debugf("cal_type=%d, from=%s, to=%s, mark=%s", c.calType, from, to, mark)
	wg := new(sync.WaitGroup)

	// 파일 이벤트 통계
	s1 := NewStats(c, FileEventStats, from, to, mark)
	wg.Add(1)
	go s1.Start(wg)

	// 네트워크 이벤트 통계
	s2 := NewStats(c, NetworkEventStats, from, to, mark)
	wg.Add(1)
	go s2.Start(wg)

	// 에이전트 이벤트 통계
	s3 := NewStats(c, AgentEventStats, from, to, mark)
	wg.Add(1)
	go s3.Start(wg)

	// 통계산출 완료까지 대기
	wg.Wait()
	log.Debugf("cal_type=%d, total_exec_time=%3.1fs", c.calType, time.Since(start).Seconds())
	return nil
}

// 사용자 자산 조회
func (c *Calculator) getMemberAssets() (map[int][]int, error) {
	m := make(map[int][]int)
	var (
		memberId int
		assetId  int
	)

	// Administrator 는 모든 자산 데이터에 대한 접근 권한을 가짐
	query := "select member_id, asset_id from mbr_asset where asset_type = 2"
	rows, err := c.engine.DB.Query(query)
	if err != nil {
		log.Error(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&memberId, &assetId)
		if err != nil {
			log.Error(err)
		}

		if _, ok := m[assetId]; !ok {
			m[assetId] = make([]int, 0)
		}
		m[assetId] = append(m[assetId], memberId)
	}
	err = rows.Err()
	if err != nil {
		log.Error(err)
	}

	return m, nil
}

func (c *Calculator) rankHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groupId, _ := strconv.Atoi(vars["groupId"])
	top, _ := strconv.Atoi(vars["top"])

	list := c.getRank(groupId, vars["category"], top)
	buf, _ := json.Marshal(list)
	w.Write(buf)
}

func (c *Calculator) getRank(groupId int, category string, top int) objs.ItemList {
	if _, ok := c.eventRank[groupId]; ok {
		if list, ok := c.eventRank[groupId][category]; ok {
			if top > 0 && len(list) > top {
				return list[:top]
			} else {
				return list
			}
		}
	}
	return nil
}

type Stats interface {
	Start(wg *sync.WaitGroup) error
}

func NewStats(calculator *Calculator, stats int, from, to, mark string) Stats {
	if stats == FileEventStats {
		//log.Debugf("### 1 - %d", stats)
		return NewFileEventStats(calculator, from, to, mark)

	} else if stats == NetworkEventStats {
		//log.Debugf("### 2 - %d", stats)
		return NewNetworkEventStats(calculator, from, to, mark)

	} else if stats == AgentEventStats {
		//log.Debugf("### 3 - %d", stats)
		return NewAgentEventStats(calculator, from, to, mark)

	} else {
		return nil
	}
}

func DetermineRankings(m map[interface{}]int64, top int) objs.ItemList {
	list := make(objs.ItemList, len(m))
	i := 0
	for k, v := range m {
		list[i] = objs.Item{k, v}
		i++
	}
	sort.Sort(sort.Reverse(list))
	if top > 0 && len(list) > top {
		return list[0:top]
	} else {
		return list
	}
}
