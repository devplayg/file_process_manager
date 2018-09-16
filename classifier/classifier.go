package classifier

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mholt/archiver"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"wins21.co.kr/sniper/golibs/network"
	"wins21.co.kr/sniper/mserver"
	"wins21.co.kr/sniper/mserver/objs"
)

type Classifier struct {
	engine          *mserver.Engine
	tmpDir          string
	dataDir         string
	errorDir        string
	archiveDir      string
	batchSize       uint
	fileStorageDir  string
	assetOrgMap     sync.Map
	geoIP           *geoip2.Reader
	interval        time.Duration
	IpPoolMap       map[int]cidranger.Ranger
	sensorMap       map[string]int
	sensorResource  map[int]objs.Resource
	partitionTables map[string]*os.File // 파티션 테이블
	exception       map[string]bool
	wg              *sync.WaitGroup
}

func NewClassifier(engine *mserver.Engine, archiveDir string, fileStorageDir string, batchSize uint, interval time.Duration) (*Classifier, error) {
	c := Classifier{
		engine:          engine,
		batchSize:       batchSize, // 일괄처리 크기
		tmpDir:          filepath.Join(engine.ProcessDir, "tmp"),
		dataDir:         filepath.Join(engine.ProcessDir, "data"),
		errorDir:        filepath.Join(engine.ProcessDir, "error"),
		archiveDir:      archiveDir,
		fileStorageDir:  fileStorageDir,
		interval:        interval,
		partitionTables: make(map[string]*os.File),
		wg:              new(sync.WaitGroup),
	}

	// GeoIP 로딩
	//if err := c.loadGeoIP(); err != nil {
	//	return &c, err
	//}

	return &c, nil
}

func (c *Classifier) Start() error {
	go func() {
		for {
			if err := c.Run(); err != nil {
				log.Error(err)
			}
			time.Sleep(c.interval)
		}
	}()
	return nil
}

func (c *Classifier) Run() error {

	// 스토리지 디렉토리 체크(.bin, .yara 파일들이 저장됨)
	if _, err := os.Stat(c.fileStorageDir); os.IsNotExist(err) {
		err := os.MkdirAll(c.fileStorageDir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	// IP Pool 로딩
	if err := c.loadIpPool(); err != nil {
		return err
	}

	// 파일 이벤트 처리
	c.wg.Add(1)
	go func() {
		if err := c.handleFileEvent(c.wg); err != nil {
			log.Error(err)
		}
	}()

	// 탐지 이벤트 처리
	c.wg.Add(1)
	go func() {
		if err := c.handleDetectionEvent(c.wg); err != nil {
			log.Error(err)
		}
	}()

	// 탐지 이벤트 처리
	c.wg.Add(1)
	go func() {
		if err := c.handleTraffic(c.wg); err != nil {
			log.Error(err)
		}
	}()

	c.wg.Wait()

	return nil
}

func (c *Classifier) handleTraffic(wg *sync.WaitGroup) error {
	defer wg.Done()

	// 압축파일 조회
	files, err := GetFiles(c.archiveDir, c.batchSize, []string{".sensor"})
	if err != nil {
		return err
	}

	// 파일이 없으면
	if len(files) == 0 {
		return nil
	}

	// 트래픽 분류
	if err := c.classifyTraffic(files); err != nil {
		return err
	}

	return nil
}

func (c *Classifier) classifyTraffic(files []string) error {

	// 상태정보
	c.sensorResource = make(map[int]objs.Resource)

	// 예외파일 처리
	exception := make(map[string]bool)

	// 임시파일 생성
	tempFile, err := ioutil.TempFile(c.tmpDir, "traffic_")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())

	// 파일병합
	var contentsLength int
	for _, f := range files {
		contents, err := c.getTrafficContents(f)
		if err != nil {
			exception[f] = true
			if !strings.HasPrefix(err.Error(), "file may be in use") { // 파일이 업로드 중이라고 판단되면
				log.Error(err)
			}
			continue
		}

		if len(contents) > 0 {
			contentsLength += len(contents)
			if _, err := tempFile.WriteString(contents); err != nil {
				log.Error(err)
				exception[f] = true // 파일 쓰기 에러
				continue
			}
		}
	}

	defer func() {
		for _, f := range files {
			if _, ok := exception[f]; !ok {
				os.Remove(f)
			}
		}
	}()

	// 입력
	tempFile.Close()
	if contentsLength > 0 {
		if err := c.insertTraffic(tempFile.Name()); err != nil {
			return err
		}
	}

	// 센서 리소스 업데이트
	if len(c.sensorResource) > 0 {
		c.updateSensorResource()
	}

	return nil
}

func (c *Classifier) updateSensorResource() error {
	for sensorId, r := range c.sensorResource {
		query := `
			update ast_sensor
            set
				cpu_usage = ?,
                mem_total = ?,
                mem_used = ?,
                home_hdd_block = ?,
                home_hdd_used = ?,
                backup_hdd_block = ?,
                backup_hdd_used = ?,
                nic_segment = ?,
                nic_port_count = ?,
                nic_line_status = ?,
                nic_link_status = ?,
                last_sms_udate = ?
			where sensor_id = ?
		`

		_, err := c.engine.DB.Exec(
			query,
			Round(r.CpuUsage, 0.05),
			r.MemTotal,
			r.MemUsed,
			r.HomeHddBlock,
			r.HomeHddUsed,
			r.BackupHddBlock,
			r.BackupHddUsed,
			r.NicSegment,
			r.NicPortCount,
			r.NicLineStatus,
			r.NicLinkStatus,
			r.Date.Format(mserver.DateDefault),
			sensorId,
		)
		if err != nil {
			log.Error(err)
		}
	}
	return nil
}

func (c *Classifier) getTrafficContents(path string) (string, error) {

	// 파일 열기
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 파일정보 읽기
	fileInfo, err := file.Stat()
	if err != nil {
		return "", err
	}

	// 시간 체크
	since := time.Since(fileInfo.ModTime()).Seconds()
	if since < 3 { // modtime이 3초가 지난 파일들만 전송이 완료된 파일로 판단
		return "", errors.New("file may be in use, " + filepath.Base(path))
	}

	// 파일 읽기
	var lines string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// 파싱
		r := strings.Split(scanner.Text(), "|")
		u, err := strconv.ParseUint(r[1], 10, 32)
		if err != nil { // IP 형식이 아니면
			log.Error(err)
			continue
		}

		ip := network.Int2ToIP(uint32(u))
		if sensorId, ok := c.sensorMap[ip.String()]; !ok {
			log.Error("invalid sensor, ", ip.String())
			continue
		} else {
			t, err := strconv.ParseInt(r[0], 10, 64)
			if err != nil {
				log.Error(err)
				continue
			}
			tm := time.Unix(t, 0)
			str := fmt.Sprintf("%s\t%d", tm.Format(mserver.DateDefault), sensorId)
			for i := 2; i < len(r); i++ {
				str += "\t" + r[i]
			}
			str += "\n"
			lines += str

			// 상태정보

			cpuUsage, _ := strconv.ParseFloat(r[2], 64)
			memTotal, _ := strconv.ParseUint(r[3], 10, 64)
			memUsed, _ := strconv.ParseUint(r[4], 10, 64)
			homeHddBlock, _ := strconv.ParseUint(r[5], 10, 64)
			homeHddUsed, _ := strconv.ParseUint(r[6], 10, 64)
			backupHddBlock, _ := strconv.ParseUint(r[7], 10, 64)
			backupHddUsed, _ := strconv.ParseUint(r[8], 10, 64)
			nicSegment, _ := strconv.ParseInt(r[9], 10, 32)
			nicPortCount, _ := strconv.ParseInt(r[10], 10, 32)
			nicLineStatus, _ := strconv.ParseInt(r[11], 10, 32)
			nicLinkStatus, _ := strconv.ParseInt(r[12], 10, 32)

			if v, ok := c.sensorResource[sensorId]; !ok {
				c.sensorResource[sensorId] = objs.Resource{
					Date:           tm,
					CpuUsage:       cpuUsage,
					MemTotal:       memTotal,
					MemUsed:        memUsed,
					HomeHddBlock:   homeHddBlock,
					HomeHddUsed:    homeHddUsed,
					BackupHddBlock: backupHddBlock,
					BackupHddUsed:  backupHddUsed,
					NicSegment:     int(nicSegment),
					NicPortCount:   int(nicPortCount),
					NicLineStatus:  int(nicLineStatus),
					NicLinkStatus:  int(nicLinkStatus),
				}
			} else {
				if tm.After(v.Date) {
					c.sensorResource[sensorId] = objs.Resource{
						Date:           tm,
						CpuUsage:       cpuUsage,
						MemTotal:       memTotal,
						MemUsed:        memUsed,
						HomeHddBlock:   homeHddBlock,
						HomeHddUsed:    homeHddUsed,
						BackupHddBlock: backupHddBlock,
						BackupHddUsed:  backupHddUsed,
						NicSegment:     int(nicSegment),
						NicPortCount:   int(nicPortCount),
						NicLineStatus:  int(nicLineStatus),
						NicLinkStatus:  int(nicLinkStatus),
					}
				}
			}
		}

	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return lines, nil
}

func (c *Classifier) handleFileEvent(wg *sync.WaitGroup) error {
	defer wg.Done()

	// 압축파일 조회
	archives, err := GetFiles(c.archiveDir, c.batchSize, []string{".gz"})
	if err != nil {
		return err
	}
	if len(archives) == 0 {
		return nil
	}

	// 임시 디렉토리에 압축 해제
	tempDir, err := c.extract2(archives)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir) // 임시 디렉토리 삭제

	// 파일이벤트 분류
	if err := c.classifyFileEvent(tempDir); err != nil {
		return err
	}

	// 파일이벤트에서 원본파일 분류
	if err := c.classifyExtraFiles(tempDir); err != nil {
		return err
	}

	// 압축파일 삭제
	for _, f := range archives {
		if _, ok := c.exception[f]; !ok { // 예외 처리된 파일(업로드 중이라고 판단되는 파일들이 제외된 파일)
			//os.Rename(f, filepath.Join(c.tmpDir, filepath.Base(f)))
			if err := os.Remove(f); err != nil {
				log.Error(err)
			}
		}
	}
	return nil
}

func (c *Classifier) handleDetectionEvent(wg *sync.WaitGroup) error {
	defer wg.Done()

	files, err := GetFiles(c.archiveDir, c.batchSize, []string{".detect"})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	for _, path := range files {
		if err := c.classifyDetectionEvent(path); err != nil {
			log.Error(err)
		}
	}

	return nil
}

func (c *Classifier) classifyDetectionEvent(path string) error {

	// 파일 열기
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// 파일정보 읽기
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	// 시간 체크
	since := time.Since(fileInfo.ModTime()).Seconds()
	if since < 3 { // modtime이 3초가 지난 파일들만 전송이 완료된 파일로 판단
		return nil
	}

	// 파일 읽기
	var lines string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		r := strings.Split(scanner.Text(), "|")

		//  2018-06-09 00:06:19|1|6565675716090789888|1521|10004|6|2010071120|65010|KR|167792651|80|US|ctldl.windowsupdate.com|/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?f9d2e255b1a95dc3|1|0|0|0|0|0|0|0|0
		//
		//  0   src_date        2018-06-09 00:06:19
		//  1   dev_id          1
		//  2   session_id      6565675716090789888
		//  3   category_major  1521
		//  4   category_minor  10004
		//  5   protocol        6
		//  6   src_ipNum       2010071120
		//  7   src_port        65010
		//  8   src_country     KR
		//  9   dst_ipNum       167792651
		// 10   dst_port        80
		// 11   dst_country     US
		// 12   domain          domain
		// 13   url             url
		// 14   risk_level      1
		// 15   result          0
		// 16   packet_cnt      0
		// 17   flow            0
		// 18   block_cnt       0
		// 19   detect_cnt      0
		// 20   http_os         0
		// 21   http_app        0
		// 22   http_hw         0

		sensorId, err := strconv.Atoi(r[1])
		if err != nil {
			log.Error(err)
			os.Rename(file.Name(), filepath.Join(c.errorDir, filepath.Base(file.Name())+".invalid_sensorid"))
			continue
		}

		// 출발지 IP
		srcIP, err := strconv.ParseUint(r[6], 10, 32)
		if err != nil {
			log.Error(err)
			os.Rename(file.Name(), filepath.Join(c.errorDir, filepath.Base(file.Name())+".invalid_srcip"))
			continue
		}
		srcGroupCode, srcObjectCode := c.getIppoolCodes(sensorId, uint32(srcIP))

		// 목적지 IP
		dstIP, err := strconv.ParseUint(r[6], 10, 32)
		if err != nil {
			log.Error(err)
			os.Rename(file.Name(), filepath.Join(c.errorDir, filepath.Base(file.Name())+".invalid_dstip"))
			continue
		}
		dstGroupCode, dstObjectCode := c.getIppoolCodes(sensorId, uint32(dstIP))

		lines += fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r[0],
			r[1],
			srcGroupCode,
			srcObjectCode,
			dstGroupCode,
			dstObjectCode,
			r[2],
			r[3],
			r[4],
			r[5],
			r[6],
			r[7],
			r[8],
			r[9],
			r[10],
			r[11],
			r[12],
			r[13],
			r[14],
			r[15],
			r[16],
			r[17],
			r[18],
			r[19],
			r[20],
			r[21],
			r[22],
		)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(lines) > 0 {
		tempFile, err := ioutil.TempFile(c.tmpDir, "detect_")
		if err != nil {
			return err
		}

		_, err = tempFile.WriteString(lines)
		if err != nil {
			return err
		}
		tempFile.Close()
		file.Close()

		if err := c.insertDetectionEvent(tempFile.Name()); err != nil {
			os.Rename(tempFile.Name(), filepath.Join(c.errorDir, filepath.Base(tempFile.Name())+".insert_failed"))
			return err
		} else {
			os.Remove(tempFile.Name())
		}
		os.Remove(path)
	}

	return nil
}

func (c *Classifier) insertDetectionEvent(filename string) error {
	query := `
		LOAD DATA LOCAL INFILE %q
		INTO TABLE log_event_common
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\n' 
		(rdate,sensor_id,ippool_src_gcode,ippool_src_ocode,ippool_dst_gcode,ippool_dst_ocode,session_id,category1,category2,protocol,src_ip,src_port,src_country,dst_ip,dst_port,dst_country,domain,url,risk_level,result,packet_count,flow,block_count,detect_count,http_os,http_app,http_hw)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(filename))
	rs, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}
	rowsAffected, _ := rs.RowsAffected()
	log.Debugf("table=%s, affected_rows=%d", "log_event_common", rowsAffected)
	return nil
}

func (c *Classifier) classifyExtraFiles(tempDir string) error {
	files, err := GetFiles(tempDir, 0, []string{".bin", ".yara"})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	for _, src := range files {
		dst := filepath.Join(c.fileStorageDir, filepath.Base(src)[0:3], filepath.Base(src))

		// 파일이 없으면
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			// Prefix 디렉토리 체크(ex: /home1/sniper/md5/abc/
			dir := filepath.Dir(dst)
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				err := os.MkdirAll(dir, os.ModePerm)
				if err != nil {
					log.Error(err)
					continue
				}
			}
			// 파일 이동
			if err := os.Rename(src, dst); err != nil {
				log.Error(err)
				continue
			}
		}
	}

	return nil
}

func (c *Classifier) classifyFileEvent(tempDir string) error {

	// 파티션테이블 맵 초기화
	c.partitionTables = make(map[string]*os.File)

	files, err := GetFiles(tempDir, 0, []string{".json"})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	// 임시파일 생성 - 파일 분석 결과
	tmpFileHash, err := ioutil.TempFile(tempDir, "pol_filehash_")
	if err != nil {
		return err
	}

	// 임시파일 생성 - 파일 이름
	tmpFileName, err := ioutil.TempFile(tempDir, "pol_filename_")
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`\t+`)

	for _, fi := range files {
		//log.Debugf("Reading file: %s", filepath.Base(fi))

		// 파일 읽기
		b, err := ioutil.ReadFile(fi)
		if err != nil {
			log.Error(err)
			continue
		}

		// JSON 파싱
		var e objs.FileEvent
		err = json.Unmarshal(b, &e)
		if err != nil {
			log.Errorf("parse error: %s (%s)", fi, err)
			os.Rename(fi, filepath.Join(c.errorDir, filepath.Base(fi)+".parse_error"))
			continue
		}

		// JSON 유효성 체크
		if len(e.Info.AnalysisId) < 1 {
			log.Errorf("invalid format: %s", fi)
			os.Rename(fi, filepath.Join(c.errorDir, filepath.Base(fi)+".invalid_id"))
			continue
		}

		// ID 파싱
		parsedId := strings.Split(e.Info.AnalysisId, "_")
		gid := strings.Join(parsedId[0:5], "_")
		sensorId, err := strconv.Atoi(parsedId[0])
		if err != nil {
			log.Errorf("invalid sensor id: %s", fi)
			os.Rename(fi, filepath.Join(c.errorDir, filepath.Base(fi)+".invalid_sensor_id"))
			continue
		}

		// 공통정보 분리
		r := objs.LogFileTrans{
			Gid:       gid,
			TransType: e.Info.Type,
			SensorId:  sensorId,
		}

		r.Rdate, _ = time.Parse(mserver.DateDefault, e.Info.Date)
		r.GroupCount = e.Info.FileCount

		// 출발지 정보 설정
		if e.Info.Type == objs.HTTP || e.Info.Type == objs.FTP {
			r.SessionId = e.Network.SessionId

			// 출발지 정보 설정
			r.SrcIp = e.Network.SrcIp
			r.SrcPort = e.Network.SrcPort
			r.SrcCountry = e.Network.SrcCountry
			r.IppoolSrcGcode, r.IppoolSrcOcode = c.getIppoolCodes(sensorId, e.Network.SrcIp)

			// 목적지 정보 설정
			r.DstIp = e.Network.DstIp
			r.DstPort = e.Network.DstPort
			r.DstCountry = e.Network.DstCountry
			r.IppoolDstGcode, r.IppoolDstOcode = c.getIppoolCodes(sensorId, e.Network.DstIp)

			r.Domain = e.Network.Domain
			r.Url = e.Network.Url

		} else if e.Info.Type == objs.POP3 || e.Info.Type == objs.SMTP {
			r.SessionId = e.Mail.MailId

			// 출발지 정보 설정
			r.SrcIp = e.Network.SrcIp
			r.SrcPort = e.Network.SrcPort
			r.SrcCountry = e.Network.SrcCountry
			r.IppoolSrcGcode, r.IppoolSrcOcode = c.getIppoolCodes(sensorId, e.Network.SrcIp)

			// 목적지 정보 설정
			r.DstIp = e.Network.DstIp
			r.DstPort = e.Network.DstPort
			r.DstCountry = e.Network.DstCountry
			r.IppoolDstGcode, r.IppoolDstOcode = c.getIppoolCodes(sensorId, e.Network.DstIp)

			// 메일 정보 설정
			r.MailSender = e.Mail.SenderAddr
			r.MailSenderName = e.Mail.SenderName
			r.MailRcpt = e.Mail.RecipientAddr
			r.MailRcptName = e.Mail.RecipientName

			// 메일 제목
			r.Domain = re.ReplaceAllString(e.Mail.Subject, " ")

		} else if e.Info.Type == objs.MTA {
			r.SessionId = e.Mail.MailId
			r.MailSender = e.Mail.SenderAddr
			r.MailSenderName = e.Mail.SenderName
			r.MailRcpt = e.Mail.RecipientAddr
			r.MailRcptName = e.Mail.RecipientName
			//r.GroupCount = e.Info.UrlCount
		} else {
			log.Debugf("skipped: %s, TransType: %d", fi, e.Info.Type)
			continue
		}

		// 로그 테이블 분류(입력 테이블 정의)
		tableKey := r.Rdate.Format("200601")
		//log.Debugf("table key: %s", tableKey)
		if _, ok := c.partitionTables[tableKey]; !ok {
			tmpFileTrans, err := getTempLogFile(tempDir, "log_filetrans_"+tableKey+"_")
			if err != nil {
				return err
			}
			c.partitionTables[tableKey] = tmpFileTrans
		}
		for idx, f := range e.Files {
			if idx == 0 {
				r.IsSeed = 1
			} else {
				r.IsSeed = 0
			}
			r.Id = f.FileId
			r.Md5 = f.Md5
			r.Sha256 = f.Sha256
			r.Size = f.Size
			r.MimeType = f.MimeType
			r.Score = f.Score
			r.MalType = f.Category
			r.FileType = f.Type
			r.SensorFlags = f.Flags
			r.Filename = f.Name
			r.CommentDynamic = strings.TrimSpace(f.CommentDynamic)
			r.CommentStatic = strings.TrimSpace(f.CommentStatic)

			// 파일 정보 생성
			lineFileTrans, lineFileHash, lineFileName := c.getLines(&r)

			// 로그 테이블
			c.partitionTables[tableKey].WriteString(lineFileTrans)

			// 스코어 테이블에 작성
			if (r.SensorFlags & 0x0001) == 0 {
				tmpFileHash.WriteString(lineFileHash)
			}

			// 파일 이름 테이블에 작성
			if r.TransType == objs.HTTP || r.TransType == objs.FTP {
				tmpFileName.WriteString(lineFileName)
			}
		}
	}

	// 벌크 입력
	for key, f := range c.partitionTables {
		f.Close()
		err = c.insertFileTrans(key, f.Name())
		if err != nil {
			log.WithFields(log.Fields{
				"file": filepath.Base(f.Name()),
			}).Error(err)
			os.Rename(f.Name(), filepath.Join(c.errorDir, filepath.Base(f.Name()))+".insert_failed")
		} else {
			//os.Remove(f.Name())
		}
	}

	// 파일 스코어 테이블
	tmpFileHash.Close()
	err = c.insertFileHash(tmpFileHash.Name())
	if err != nil {
		log.Error(err)
		os.Rename(tmpFileHash.Name(), filepath.Join(c.errorDir, filepath.Base(tmpFileHash.Name())))
	} else {
		//os.Remove(tmpFileHash.Name())
	}

	// 파일이름 테이블
	tmpFileName.Close()
	err = c.insertFileName(tmpFileName.Name())
	if err != nil {
		log.Error(err)
		os.Rename(tmpFileName.Name(), filepath.Join(c.errorDir, filepath.Base(tmpFileName.Name())))
	} else {
		//os.Remove(tmpFileName.Name())
	}

	return nil
}

func (c *Classifier) extract(files []string) (string, error) {
	c.exception = make(map[string]bool)

	tempDir, err := ioutil.TempDir(c.tmpDir, "")
	if err != nil {
		return "", err
	}
	for _, archiveFile := range files {
		// 압축해제
		log.Debugf("extracting [%s] to [%s]", archiveFile, tempDir)
		err := archiver.TarGz.Open(archiveFile, tempDir)
		if err != nil { // 압축해제 실패 시
			if strings.HasSuffix(err.Error(), "unexpected EOF") { // 파일이 업로드 중이라고 판단되면
				log.Debugf("uploading: %s", filepath.Base(archiveFile))

				file, err := os.Stat(archiveFile)
				if err != nil {
					log.Error(err)
					continue
				}
				now := time.Now()
				since := time.Since(file.ModTime()).Seconds()
				if since > 60 { // ModTime이 60초가 지나도 EOF에러 발생하면
					log.Errorf("invalid gz, name=%s, since=%3.1f", archiveFile, since)
					log.Errorf("name=%s, now=%v, mod=%v", archiveFile, now, file.ModTime())
					if err := os.Rename(archiveFile, archiveFile+".invalid"); err != nil { // 오류로 판단
						log.Error(err)
						continue
					}
				} else { // 파일이 업로드 중이라고 판단이 되면 (기준: mod. time)
					log.Debugf("exception: %s", filepath.Base(archiveFile))
					c.exception[archiveFile] = true
				}

			} else {
				log.Error(err)
				if err := os.Rename(archiveFile, archiveFile+".invalid"); err != nil { // 압축형식 오류 시
					log.Error(err)
				}
			}
		}
	}

	return tempDir, nil
}

func (c *Classifier) extract2(files []string) (string, error) {
	c.exception = make(map[string]bool)

	tempDir, err := ioutil.TempDir(c.tmpDir, "")
	if err != nil {
		return "", err
	}
	for _, archiveFile := range files {
		// 압축 해제
		if err := c.extractEach(archiveFile, tempDir); err != nil {
			log.Error(err)
		}
	}

	return tempDir, nil
}

func (c *Classifier) extractEach(archiveFile, moveTo string) error {
	// 임시 디렉토리 생성
	tempDir, err := ioutil.TempDir(c.tmpDir, "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	// 압축 해제
	log.Debugf("extracting [%s] to [%s]", archiveFile, tempDir)
	if err := archiver.TarGz.Open(archiveFile, tempDir); err != nil { // 압축 해제 실패 시
		if strings.HasSuffix(err.Error(), "unexpected EOF") { // unexpected EOF 에러 발생 시
			file, err := os.Stat(archiveFile)
			if err != nil {
				if err2 := os.Rename(archiveFile, archiveFile+".invalid"); err2 != nil { // 파일형식 오류로 판단
					log.Error(err2)
				}
				return err
			}
			//now := time.Now()
			since := time.Since(file.ModTime()).Seconds()
			if since > 120 { // ModTime이 120초가 지나도 EOF에러 발생하면
				//			log.Errorf("invalid gz, name=%s, since=%3.1f", archiveFile, since)
				//			log.Errorf("name=%s, now=%v, mod=%v", archiveFile, now, file.ModTime())
				if err2 := os.Rename(archiveFile, archiveFile+".invalid"); err2 != nil { // 파일형식 오류로 판단
					log.Error(err2)
				}
				return errors.New("invalid format: " + archiveFile)
			} else { // 파일이 업로드 중이라고 판단이 되면 (기준: mod. time)
				log.Debugf("exception: %s", filepath.Base(archiveFile))
				c.exception[archiveFile] = true
				return nil
			}

		} else { // 그 외 에러이면
			if err2 := os.Rename(archiveFile, archiveFile+".invalid"); err2 != nil { // 압축형식 오류 시
				log.Error(err2)
			}
			return err
		}
	} else { // 압축 해제 성공 시

		// 파일 읽기
		files, err :=  ioutil.ReadDir(tempDir)
		if err != nil {
			c.exception[archiveFile] = true
			return err
		}

		// 파일 이동
		for _, f := range files {
			if err2 := os.Rename(filepath.Join(tempDir, f.Name()), filepath.Join(moveTo, f.Name()) ); err2 != nil {
				log.Error(err2)
			}
			//log.Debugf("move: %s", f.Name())
		}

		return nil

	}
}

func getTempLogFile(dir, prefix string) (*os.File, error) {
	return ioutil.TempFile(dir, prefix)
}

func (c *Classifier) Retry(target string) error {
	if fi, err := os.Stat(target); os.IsNotExist(err) {
		return errors.New("target not found: " + target)
	} else {
		if fi.IsDir() { // 디렉토리면
			files, err := ioutil.ReadDir(target)
			if err != nil {
				return err
			}
			for _, f := range files {
				if err := c.deal(filepath.Join(target, f.Name())); err != nil {
					log.Error(err)
				}
			}
		} else { // 파일이면
			if err := c.deal(target); err != nil {
				log.Error(err)
			}
		}
	}
	return nil
}

func (c *Classifier) deal(path string) error {
	name := filepath.Base(path)

	if strings.HasPrefix(name, "log_filetrans_") { // 로그 파일이면
		tableKey, err := findTableKey(name)
		if err != nil {
			return err
		} else {
			if err := c.insertFileTrans(tableKey, path); err != nil {
				return err
			} else {
				if err := os.Remove(path); err != nil {
					return err
				}
			}
		}
	} else if strings.HasPrefix(name, "pol_filehash_") { // Score 파일이면
		if err := c.insertFileHash(path); err != nil {
			return err
		} else {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	} else if strings.HasPrefix(name, "pol_filename_") { // 파일 이름이면
		if err := c.insertFileName(path); err != nil {
			return err
		} else {
			if err := os.Remove(path); err != nil {
				return err
			}
		}

	} else {
		return errors.New("invalid file: " + name)
	}

	return nil
}

func (c *Classifier) classify(files []string) error {
	return nil
}

func findTableKey(name string) (string, error) {
	r, _ := regexp.Compile(`log_filetrans_(\d+)_.*`)
	list := r.FindStringSubmatch(name)
	if len(list) == 1 {
		return "", errors.New("invalid table key format")
	} else {
		return list[1], nil
	}
}

func (c *Classifier) getIppoolCodes(sensorId int, ip uint32) (int, int) {
	netIP := network.Int2ToIP(ip)
	return c._getIppoolCodes(sensorId, netIP)
}

func (c *Classifier) _getIppoolCodes(sensorId int, ip net.IP) (int, int) {

	//log.Debugf("### IP=%s, sensor_id=%d ", ip.String(), sensorId)
	if _, ok := c.IpPoolMap[sensorId]; !ok {
		return 0, 0
	}
	list, _ := c.IpPoolMap[sensorId].ContainingNetworks(ip)
	if len(list) < 1 {
		return 0, 0
	}

	if len(list) == 1 {
		return list[0].(objs.IpPool).FolderId, list[0].(objs.IpPool).IppoolId
	}

	smallest := list[0]
	for i := 1; i < len(list); i++ {
		if list[i].(objs.IpPool).HostCount < smallest.(objs.IpPool).HostCount {
			smallest = list[i]
		}
	}
	//log.Debug("### " + smallest.(objs.IpPool).Name)
	return smallest.(objs.IpPool).FolderId, smallest.(objs.IpPool).IppoolId
}

func (c *Classifier) loadGeoIP() error {
	geoIpPath, _ := filepath.Abs(os.Args[0])
	geoIpPath = filepath.Join(filepath.Dir(geoIpPath), "libs", "GeoLite2-Country.mmdb")
	geoIP2, err := geoip2.Open(geoIpPath)
	if err != nil {
		return err
	}
	c.geoIP = geoIP2

	return nil
}

func (c *Classifier) loadIpPool() error {
	// IPPool 조회
	query := `
		select t.sensor_id, t1.ip sensor_ip, folder_id, ippool_id, t.name, concat(t.ip, '/', t.cidr) ip_cidr
		from ast_ippool t left outer join ast_sensor t1 on t1.sensor_id = t.sensor_id
	`
	var ippools []objs.IpPool

	rows, err := c.engine.DB.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	// 데이터 맵 생성
	for rows.Next() {
		e := objs.IpPool{}
		if err := rows.Scan(&e.SensorId, &e.SensorIP, &e.FolderId, &e.IppoolId, &e.Name, &e.IpCidr); err != nil {
			return err
		}
		if err := e.UpdateIpNet(); err != nil {
			return err
		}
		ippools = append(ippools, e)
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	// 센서별 IP Pool 분류
	c.IpPoolMap = make(map[int]cidranger.Ranger)
	c.sensorMap = make(map[string]int)
	for _, a := range ippools {
		c.sensorMap[a.SensorIP] = a.SensorId
		a.UpdateIpNet()
		if _, ok := c.IpPoolMap[a.SensorId]; !ok {
			ranger := cidranger.NewPCTrieRanger()
			c.IpPoolMap[a.SensorId] = ranger
		}

		r := c.IpPoolMap[a.SensorId]
		err := r.Insert(a)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Classifier) getLines(r *objs.LogFileTrans) (string, string, string) {
	lineFileTrans := fmt.Sprintf("%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%d\t%d\t%d\t%s\t%d\t%s\t%s\r\n",
		r.Rdate.Format(mserver.DateDefault),
		r.IsSeed,
		r.Id,
		r.Gid,
		r.TransType,
		r.SensorId,
		r.IppoolSrcGcode,
		r.IppoolSrcOcode,
		r.IppoolDstGcode,
		r.IppoolDstOcode,
		r.Md5,
		r.Sha256,
		r.SrcIp,
		r.SrcPort,
		r.SrcCountry,
		r.DstIp,
		r.DstPort,
		r.DstCountry,
		r.Domain,
		r.Url,
		r.Filename,
		r.MailSender,
		r.MailSenderName,
		r.MailRcpt,
		r.MailRcptName,
		r.MalType,
		r.FileType,
		r.MimeType,
		r.Size,
		r.Score,
		r.SensorFlags,
		r.SessionId,
		r.GroupCount,
		r.CommentDynamic,
		r.CommentStatic,
	)

	lineFileHash := fmt.Sprintf("%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n",
		r.Md5,
		r.Sha256,
		r.Score,
		r.MalType,
		r.FileType,
		r.MimeType,
		r.Size,
		r.SensorFlags,
		r.Filename,
		r.CommentDynamic,
		r.CommentStatic,
		r.Rdate.Format(mserver.DateDefault),
		r.Rdate.Format(mserver.DateDefault),
	)

	lineFileName := fmt.Sprintf("%s\t%s\n",
		r.Md5,
		r.Filename,
	)

	return lineFileTrans, lineFileHash, lineFileName
}

func (c *Classifier) insertFileTrans(tableKey, path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE log_filetrans_%s
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(rdate,is_seed,id,gid,trans_type,sensor_id,ippool_src_gcode,ippool_src_ocode,ippool_dst_gcode,ippool_dst_ocode,md5,sha256,src_ip,src_port,src_country,dst_ip,dst_port,dst_country,domain,url,file_name,mail_sender,mail_sender_name,mail_recipient,mail_recipient_name,mal_type,file_type,content,file_size,score,sensor_flags,session_id,group_count,comment_dynamic,comment_static);
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path), tableKey)
	rs, err := c.engine.DB.Exec(query)
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("table=log_filetrans_%s, affected_rows=%d", tableKey, rowsAffected)
	}
	return err
}

func (c *Classifier) insertFileHash(path string) error {

	var query string

	// 임시 테이블 초기화
	query = "truncate table pol_filehash_temp"
	_, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	// 데이터를 임시테이블에 입력
	query = `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE pol_filehash_temp 
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, comment_dynamic, comment_static, rdate, udate)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	_, err = c.engine.DB.Exec(query)
	if err != nil {
		return err
	}

	// 중복 업데이트(필요한 필드만)
	query = `
		insert into pol_filehash(md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, comment_dynamic, comment_static, rdate, udate)
		select md5, sha256, score, mal_type, file_type, content, size, sensor_flags, file_name, comment_dynamic, comment_static, rdate, udate
		from pol_filehash_temp
		on duplicate key update
			sha256 = values(sha256),
			score = values(score),
			mal_type = values(mal_type),
			file_type = values(file_type),
			content = values(content),
			size = values(size),
			sensor_flags = values(sensor_flags),
			comment_dynamic = values(comment_dynamic),
			comment_static = values(comment_static),
			udate = values(udate)
	`

	rs, err := c.engine.DB.Exec(query)
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("table=pol_filehash, affected_rows=%d", rowsAffected)
	}
	return err
}

func (c *Classifier) insertFileName(path string) error {
	query := `
		LOAD DATA LOCAL INFILE '%s' REPLACE INTO TABLE pol_filename
		FIELDS TERMINATED BY '\t' 
		LINES TERMINATED BY '\n' 
		(md5, name)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(path))
	rs, err := c.engine.DB.Exec(query)
	if err == nil {
		rowsAffected, _ := rs.RowsAffected()
		log.Debugf("table=pol_filename, affected_rows=%d", rowsAffected)
	}
	return err
}

func (c *Classifier) insertTraffic(filename string) error {
	query := `
		LOAD DATA LOCAL INFILE %q
		INTO TABLE log_traffic
		FIELDS TERMINATED BY '\t'
		LINES TERMINATED BY '\n' 
		(date,sensor_id,cpu_use_per,mem_total,mem_used,home_hdd_block,home_hdd_used,backup_hdd_block,backup_hdd_used,nic_segment,nic_port_count,nic_line_status,nic_link_status,pps_tot_in_1,pps_tot_out_1,size_tot_in_1,size_tot_out_1,drop_tot_in_1,drop_tot_out_1,pps_tot_in_2,pps_tot_out_2,size_tot_in_2,size_tot_out_2,drop_tot_in_2,drop_tot_out_2,pps_tot_in_3,pps_tot_out_3,size_tot_in_3,size_tot_out_3,drop_tot_in_3,drop_tot_out_3,pps_tot_in_4,pps_tot_out_4,size_tot_in_4,size_tot_out_4,drop_tot_in_4,drop_tot_out_4)
	`
	query = fmt.Sprintf(query, filepath.ToSlash(filename))
	rs, err := c.engine.DB.Exec(query)
	if err != nil {
		return err
	}
	rowsAffected, _ := rs.RowsAffected()
	log.Debugf("table=%s, affected_rows=%d", "log_traffic", rowsAffected)
	return nil
}

func GetFiles(dir string, count uint, exts []string) ([]string, error) {
	m := make(map[string]bool)
	for _, ext := range exts {
		m[strings.ToLower(ext)] = true
	}

	var i uint
	files := make([]string, 0)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Mode().IsRegular() {
			if exts == nil {
				if info.Size() == 0 {
					//os.Remove(path)
					return nil
				}
				files = append(files, path)
				i++
			} else {
				if _, ok := m[filepath.Ext(path)]; ok {
					if info.Size() == 0 {
						//os.Remove(path)
						return nil
					}
					files = append(files, path)
					i++
				}
			}
		}

		if count > 0 && i == count {
			return io.EOF
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return nil, err
	}

	return files, nil
}

func Round(x, unit float64) float64 {
	return math.Round(x/unit) * unit
}
