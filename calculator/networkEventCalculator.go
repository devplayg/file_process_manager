package calculator

import (
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
	"wins21.co.kr/sniper/mserver/objs"
)

type networkEventCalculator struct {
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

func NewNetworkEventStats(calculator *Calculator, from, to, mark string) *networkEventCalculator {
	return &networkEventCalculator{
		calculator: calculator,
		dataMap:    make(objs.DataMap),
		dataRank:   make(objs.DataRank),
		tables:     map[string]bool{},
		from:       from,
		to:         to,
		mark:       mark,
	}
}

func (c *networkEventCalculator) Start(wg *sync.WaitGroup) error {
	defer wg.Done()
	start := time.Now()
	//time.Sleep(1 * time.Second)
	log.Debugf("stats=%s, rows=%d, time=%3.1fs", "network", c.total, time.Since(start).Seconds())
	return nil
}

func (c *networkEventCalculator) produceStats() error {
	return nil
}

func (c *networkEventCalculator) insert() error {
	return nil
}
