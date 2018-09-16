package resmanager

import (
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	log "github.com/sirupsen/logrus"
	"wins21.co.kr/sniper/mserver"
	"encoding/json"
	"math"
)

type ResManager struct {
	engine  *mserver.Engine
	dataDir string
}

func NewResManager(engine *mserver.Engine, dataDir string) *ResManager {
	resManager := ResManager{
		engine:  engine,
		dataDir: dataDir,
	}
	return &resManager
}

func (c *ResManager) Start() {
	cpu, cpuInfo := GetCpuResource()
	log.Debug(cpu)
	log.Debug(cpuInfo)
	mem := GetMemoryResource()
	log.Debug(mem)
	partitions := make([]*disk.UsageStat, 0)
	diskRes := GetDiskResource()
	for _, p := range diskRes {
		u, _ := disk.Usage(p.Mountpoint)
		partitions = append(partitions, u)
	}
	log.Debug(partitions)
	err := c.update(cpu, cpuInfo, mem, partitions)
	checkErr(err)
}

func (c *ResManager) update(cpu []float64, cpuInfo []cpu.InfoStat, mem *mem.VirtualMemoryStat, partitions []*disk.UsageStat) error {
	var diskTotal uint64
	var diskUsed uint64
	for _, p := range partitions {
		if p.Path == c.dataDir {
			diskTotal = p.Total
			diskUsed = p.Used
		}
	}
	cpuComment, _ := json.Marshal(cpuInfo)
	memComment, _ := json.Marshal(mem)
	diskComment, _ := json.Marshal(partitions)
	query := `
		update ast_server
		set cpu_usage = ?, mem_total = ?, mem_used = ?, disk_total = ?, disk_used = ?,
			cpu_comment = ?, mem_comment = ?, disk_comment = ?, last_sms_udate = now()
		where category1 = 1 and category2 = 1
	`
	_, err := c.engine.DB.Exec(query, math.Round(cpu[0]/0.05) * 0.05, mem.Total, mem.Used, diskTotal, diskUsed, string(cpuComment), string(memComment), string(diskComment))
	return err
}

func GetCpuResource() ([]float64, []cpu.InfoStat) {
	usage, err := cpu.Percent(0, false)
	checkErr(err)
	info, err := cpu.Info()
	return usage, info
}

func GetMemoryResource() *mem.VirtualMemoryStat {
	memoryMetrics, err := mem.VirtualMemory()
	checkErr(err)
	return memoryMetrics
}

func GetDiskResource() []disk.PartitionStat {
	parts, err := disk.Partitions(false)
	checkErr(err)
	return parts
}

//func printUsage(u *disk.UsageStat) {
//	fmt.Println(u.Path + "\t" + strconv.FormatFloat(u.UsedPercent, 'f', 2, 64) + "% full.")
//	fmt.Println("Total: " + strconv.FormatUint(u.Total/1024/1024/1024, 10) + " GiB")
//	fmt.Println("Free:  " + strconv.FormatUint(u.Free/1024/1024/1024, 10) + " GiB")
//	fmt.Println("Used:  " + strconv.FormatUint(u.Used/1024/1024/1024, 10) + " GiB")
//}

func checkErr(err error) {
	if err != nil {
		log.Error(err)
	}
}
