package calculator

import (
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
	"wins21.co.kr/sniper/mserver/objs"
)

type agentEventCalculator struct {
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

func NewAgentEventStats(calculator *Calculator, from, to, mark string) *agentEventCalculator {
	return &agentEventCalculator{
		calculator: calculator,
		dataMap:    make(objs.DataMap),
		dataRank:   make(objs.DataRank),
		tables:     map[string]bool{ // true:전체데이터 유지, false: TopN 데이터만 유지
		},
		from: from,
		to:   to,
		mark: mark,
	}
}

func (c *agentEventCalculator) Start(wg *sync.WaitGroup) error {
	defer wg.Done()
	start := time.Now()
	//time.Sleep(3 * time.Second)
	log.Debugf("stats=%s, rows=%d, time=%3.1fs", "agent", c.total, time.Since(start).Seconds())
	return nil
}

func (c *agentEventCalculator) produceStats() error {
	return nil
}

func (c *agentEventCalculator) insert() error {

	return nil
}
