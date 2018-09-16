package objs

import (
	"net"
	"wins21.co.kr/sniper/golibs/network"
)

type Server struct {
	ServerID uint
	Hostname string
	Port     uint32
	Username string
	Password string
}

type IpPool struct {
	IppoolId  int
	FolderId  int
	SensorId  int
	SensorIP  string
	IpCidr    string
	Name      string
	IPNet     net.IPNet
	HostCount int
}

type Agent struct {
	Guid               string
	Name               string
	State              int
	Mac                string
	IP                 uint32
	IPStr              string
	OsVersionNumber    float32
	OsBit              int
	OsIsServer         int
	ComputerName       string
	Eth                string
	FullPolicyVersion  int
	TodayPolicyVersion int
	Rdate              string
	Udate              string
	LastInspectionDate string
}

func (a IpPool) Network() net.IPNet {
	return a.IPNet
}

func (a *IpPool) UpdateIpNet() error {
	_, ipNet, _ := net.ParseCIDR(a.IpCidr)
	a.IPNet = *ipNet

	cidr, _ := a.IPNet.Mask.Size()
	a.HostCount = network.GetNetworkHostCount(cidr)

	return nil
}
