package agentcollector

import (
	"database/sql"
	"fmt"
	"github.com/mholt/archiver"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"net"
	"strings"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/objs"
	"errors"
	"github.com/yl2chen/cidranger"
)

const (
	InputJsonDateFormat = "2006-01-02 15:04:05.000"
)

type collector struct {
	engine      *mserver.Engine
	tmpDir      string
	dataDir     string
	lastSeconds uint
	archiveDir  string
	batchSize   uint
	geoIP       *geoip2.Reader
	//IpPoolMap   map[int]cidranger.Ranger
	ippoolRanger cidranger.Ranger
}

func NewCollector(engine *mserver.Engine, lastSeconds uint, archiveDir string, batchSize uint) *collector {
	return &collector{
		engine:      engine,
		archiveDir:  archiveDir,  // APTX-AM 로그 디렉토리
		lastSeconds: lastSeconds, // 최근 N초 이내에 접속한 에이전트
		batchSize:   batchSize,   // 일괄처리 크기
		tmpDir:      filepath.Join(engine.ProcessDir, "tmp"),
		dataDir:     filepath.Join(engine.ProcessDir, "data"),
	}
}

func (c *collector) ProcessStatus() {

	// APTX-AM 서버목록 조회
	servers, err := c.getServers()
	if err != nil {
		log.Error(err)
		return
	}

	// IP Pool 조회
	if err := c.loadIpPool(); err != nil {
		log.Error(err)
	}

	// 에이전트 정보 조회
	for _, s := range servers {
		if err := c.collect(s); err != nil {
			log.Error(err)
		}
	}

	// 업데이트
	if err := c.update(); err != nil {
		log.Error(err)
		return
	}

	// 임시 테이블 초기화
	if err := c.clean(); err != nil {
		log.Error(err)
		return
	}
}

func (c *collector) ProcessLogs() {
	dir := c.archiveDir

	var i uint
	tmpDir, err := ioutil.TempDir(c.tmpDir, "agent_")
	if err != nil {
		log.Error(err)
	}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Mode().IsRegular() && strings.HasSuffix(info.Name(), ".tar.gz") {
			log.Debugf("extracting file from %s", filepath.Base(path))
			if err = archiver.TarGz.Open(path, tmpDir); err != nil {
				return err
			}
			i++
			err = os.Remove(path)
			if err != nil {
				log.Error(err)
			}
		}

		if i == c.batchSize {
			return io.EOF
		}
		return nil
	})

	if err != nil {
		log.Error(err)
	}

	if i > 0 {
		if err := c.insertLogs(tmpDir); err != nil {
			log.Error(err)
		} else {
			if err := os.RemoveAll(tmpDir); err != nil {
				log.Error(err)
			}
		}
	} else {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Error(err)
		}
	}
}

func (c *collector) loadIpPool() error {

	// IPPool 조회
	query := `
		select ippool_id, name, concat(ip, '/', cidr) ip_cidr 
		from ast_ippool
		where sensor_id in (
			select sensor_id
			from ast_sensor_option
			where category = 1 and opt = 1 and enabled = 1
		);
	`

	rows, err := c.engine.DB.Query(query)
	if err != nil {
		log.Error(err)
	}
	defer rows.Close()

	// 데이터 맵 생성
	c.ippoolRanger = cidranger.NewPCTrieRanger()
	for rows.Next() {
		e := objs.IpPool{}
		if err := rows.Scan(&e.IppoolId, &e.Name, &e.IpCidr); err != nil {
			return err
		}
		if err := e.UpdateIpNet(); err != nil {
			return err
		}
		c.ippoolRanger.Insert(e)
	}

	err = rows.Err()
	if err != nil {
		return err
	}

	return nil
}

func (c *collector) getIppoolCode(ip net.IP) int {
	list, _ := c.ippoolRanger.ContainingNetworks(ip)
	//log.Debugf("### 1, length=%d", len(list))
	if len(list) < 1 {
		return 0
	} else if len(list) == 1 {
		return list[0].(objs.IpPool).IppoolId
	}
	//log.Debug("### 3")
	//log.Debugf("### Len: %d", len(list))
	smallest := list[0]
	for i := 1; i < len(list); i++ {
		if list[i].(objs.IpPool).HostCount < smallest.(objs.IpPool).HostCount {
			smallest = list[i]
		}
	}
	//log.Debug("### " + smallest.(objs.IpPool).Name)
	return smallest.(objs.IpPool).IppoolId
}

func (c *collector) insertLogs(dir string) error {
	result := true
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasPrefix(filepath.Base(path), "audit_log") {
			if err:= c.insertAuditLogs(path); err != nil {
				log.Error(err)
				result = false
			}
		} else if strings.HasPrefix(filepath.Base(path), "update_result") {
			if err:= c.insertVersionLogs(path); err != nil {
				log.Error(err)
				result = false
			}
		} else if strings.HasPrefix(filepath.Base(path), "event") {
			if err:= c.insertEventLogs(path); err != nil {
				log.Error(err)
				result = false
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if result  {
		return nil
	} else {
		return errors.New("error")
	}
}

func (c *collector) insertAuditLogs(path string) error {
	var query string

	query = fmt.Sprintf("LOAD DATA LOCAL INFILE '%s' INTO TABLE adt_agent_temp(rdate, guid, category, s1, s2, n1, n2)", filepath.ToSlash(path))
	_, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	query = `
		insert into adt_agent
		select t.*,
					t1.amserver_id,
					t1.ippool_id,
					t1.name,
					t1.state,
					t1.mac,
					t1.ip,
					t1.os_version_number,
					t1.os_bit,
					t1.os_is_server,
					t1.computer_name,
					t1.eth,
					t1.full_policy_version,
					t1.today_policy_version,
					t1.rdate rdate2,
					t1.rdate udate2,
					t1.last_inspection_date
		from adt_agent_temp t left outer join ast_agent t1 on t1.guid = t.guid
	`
	_, err = c.engine.DB.Exec(query)
	if err != nil {
		return err
	}
	os.Remove(path)

	query = "truncate table adt_agent_temp"
	_, err = c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (c *collector) insertVersionLogs(path string) error {
	query := fmt.Sprintf("LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE log_agent_update_result(guid, filepath, file_version, cause, result, udate)", filepath.ToSlash(path))
	_, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}
	os.Remove(path)

	return nil
}

func (c *collector) insertEventLogs(path string) error {
	var query string

	query = fmt.Sprintf("LOAD DATA LOCAL INFILE '%s' INTO TABLE log_agent_event CHARACTER SET utf8 (rdate,guid,log_type,item_type,item_path1,item_path2,item_id,item_name,item_md5,action,result,str1,str2,str3,n1,n2,n3)", filepath.ToSlash(path))
	_, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	query = `
		insert into log_agent_event_extended
		select t.*,
					t1.amserver_id,
					t1.ippool_id,
					t1.name,
					t1.state,
					t1.mac,
					t1.ip,
					t1.os_version_number,
					t1.os_bit,
					t1.os_is_server,
					t1.computer_name,
					t1.eth,
					t1.full_policy_version,
					t1.today_policy_version,
					t1.rdate rdate2,
					t1.rdate udate2,
					t1.last_inspection_date
		from log_agent_event t left outer join ast_agent t1 on t1.guid = t.guid
	`
	_, err = c.engine.DB.Exec(query)
	if err != nil {
		return err
	}
	os.Remove(path)

	query = "truncate table log_agent_event"
	_, err = c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (c *collector) getServers() ([]objs.Server, error) {
	query := `
		select 	server_id, hostname, port, 
				aes_decrypt(from_base64(username), 'WINS SNIPER APTX 4.0') username,
				aes_decrypt(from_base64(password), 'WINS SNIPER APTX 4.0') password
		from ast_server
		where category1 = ? and category2 = ?
	`

	var servers []objs.Server
	rows, err := c.engine.DB.Query(query, 1, 2)
	if err != nil {
		return nil ,err
	}
	defer rows.Close()

	// 데이터 맵 생성
	for rows.Next() {
		s := objs.Server{}
		err := rows.Scan(&s.ServerID, &s.Hostname, &s.Port, &s.Username, &s.Password)
		if err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return servers, nil
}

func (c *collector) clean() error {
	query := "truncate table ast_agent_temp"
	_, err := c.engine.DB.Exec(query)
	return err
}

func (c *collector) collect(s objs.Server) error {
	db, err := c.getDB(s)
	if err != nil {
		return err
	}
	defer db.Close()

	// 에이전트 상태정보 조회
	list, err := c.getAgents(db)
	if err != nil {
		return err
	}

	// 파일에 저장
	f, err := ioutil.TempFile(c.tmpDir, "agent_")
	if err != nil {
		return err
	}
	if !c.engine.IsDebug() {
		defer os.Remove(f.Name())
	}
	for _, r := range list {
		ip := net.ParseIP(r.IPStr)
		//log.Debugf("IP: %s", r.IPStr)
		ippool := c.getIppoolCode(ip)
		//log.Debugf("IP Pool: %d", ippool)

		line := fmt.Sprintf("%s\t%d\t%d\t%s\t%d\t%s\t%d\t%3.1f\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			r.Guid,
			s.ServerID,
			ippool, // IP Pool
			r.Name,
			r.State,
			r.Mac,
			r.IP,
			r.OsVersionNumber,
			r.OsBit,
			r.OsIsServer,
			r.ComputerName,
			r.Eth,
			r.FullPolicyVersion,
			r.TodayPolicyVersion,
			r.Rdate,
			r.Udate,
			r.LastInspectionDate,
		)

		f.WriteString(line)
	}
	f.Close()

	// Insert
	if err := c.insert(f.Name()); err != nil {
		return err
	}

	return nil
}

func (c *collector) getAgents(db *sql.DB) ([]objs.Agent, error) {
	query := `
		select  guid,
				ifnull(name, '') name,
				ifnull(state, 0) state,
				ifnull(mac, '') mac,
				ip,
				inet_ntoa(ip) ip_str,
				os_version_number,
				os_bit,
				os_is_server,
				computer_name,
				eth,
				full_policy_version,
				today_policy_version,
				rdate,
				udate,
				ifnull(last_inspection_date, '') last_inspection_date
		from ast_agent
		where udate >= date_add(now(), interval (? * -1) second)
	`

	var agents []objs.Agent
	rows, err := db.Query(query, c.lastSeconds)
	if err != nil {
		log.Error(err)
	}
	defer rows.Close()

	// 데이터 맵 생성
	for rows.Next() {
		a := objs.Agent{}
		err := rows.Scan(
			&a.Guid,
			&a.Name,
			&a.State,
			&a.Mac,
			&a.IP,
			&a.IPStr,
			&a.OsVersionNumber,
			&a.OsBit,
			&a.OsIsServer,
			&a.ComputerName,
			&a.Eth,
			&a.FullPolicyVersion,
			&a.TodayPolicyVersion,
			&a.Rdate,
			&a.Udate,
			&a.LastInspectionDate,
		)

		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return agents, err
}

func (c *collector) getDB(s objs.Server) (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?allowAllFiles=true&timeout=30s&charset=utf8&loc=%s",
		s.Username,
		s.Password,
		s.Hostname,
		s.Port,
		"aptxam",
		"Asia%2FSeoul")
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, err
	}

	log.Debugf("connecting to APTX-AM server(%s:%d)", s.Hostname, s.Port)

	if err := db.Ping(); err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(1)

	return db, nil
}

func (c *collector) insert(path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE ast_agent_temp 
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := c.engine.DB.Exec(query)
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("db=ast_agent_temp, affected_rows=%d", rowsAffected)
	}
	return err
}

func (c *collector) update() error {
	query := `
		insert into ast_agent
		select  guid,
				amserver_id,
				ippool_id,
				name,
				state,
				mac,
				ip,
				os_version_number,
				os_bit,
				os_is_server,
				computer_name,
				eth,
				full_policy_version,
				today_policy_version,
				rdate,
				udate,
				last_inspection_date
		from ast_agent_temp
			on duplicate key update
				amserver_id = values(amserver_id),
				ippool_id = values(ippool_id),
				mac = values(mac),
				ip = values(ip),
				os_version_number = values(os_version_number),
				os_bit = values(os_bit),
				os_is_server = values(os_is_server),
				computer_name = values(computer_name),
				eth = values(eth),
				full_policy_version=values(full_policy_version),
				today_policy_version=values(today_policy_version),
				udate = values(udate),
				last_inspection_date = values(last_inspection_date)
	`
	query = fmt.Sprintf(query)
	rs, err := c.engine.DB.Exec(query)
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("db=ast_agent, affected_rows=%d", rowsAffected)
	}
	return err
}
