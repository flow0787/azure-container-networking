// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package models

import (
	"net"

	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Azure/azure-container-networking/platform"
)

//todo: linux has different def for this.
type route interface{}

// ExternalInterface is a host network interface that bridges containers to external networks.
type ExternalInterface struct {
	Name        string
	Networks    map[string]*network
	Subnets     []string
	BridgeName  string
	DNSInfo     DNSInfo
	MacAddress  net.HardwareAddr
	IPAddresses []*net.IPNet
	Routes      []*route
	IPv4Gateway net.IP
	IPv6Gateway net.IP
}

// A container network is a set of endpoints allowed to communicate with each other.
type network struct {
	Id               string
	HnsId            string `json:",omitempty"`
	Mode             string
	VlanId           int
	Subnets          []SubnetInfo
	Endpoints        map[string]*endpoint
	extIf            *ExternalInterface
	DNS              DNSInfo
	EnableSnatOnHost bool
	NetNs            string
	SnatBridgeIP     string
}

// NetworkInfo contains read-only information about a container network.
type NetworkInfo struct {
	MasterIfName     string
	Id               string
	Mode             string
	Subnets          []SubnetInfo
	DNS              DNSInfo
	Policies         []policy.Policy
	BridgeName       string
	EnableSnatOnHost bool
	NetNs            string
	Options          map[string]interface{}
}

// SubnetInfo contains subnet information for a container network.
type SubnetInfo struct {
	Family  platform.AddressFamily
	Prefix  net.IPNet
	Gateway net.IP
}

// DNSInfo contains DNS information for a container network or endpoint.
type DNSInfo struct {
	Suffix  string
	Servers []string
	Options []string
}

// Endpoint represents a container network interface.
type endpoint struct {
	Id                       string
	HnsId                    string `json:",omitempty"`
	SandboxKey               string
	IfName                   string
	HostIfName               string
	MacAddress               net.HardwareAddr
	InfraVnetIP              net.IPNet
	LocalIP                  string
	IPAddresses              []net.IPNet
	Gateways                 []net.IP
	DNS                      DNSInfo
	Routes                   []RouteInfo
	VlanID                   int
	EnableSnatOnHost         bool
	EnableInfraVnet          bool
	EnableMultitenancy       bool
	AllowInboundFromHostToNC bool
	AllowInboundFromNCToHost bool
	HostNCApipaEndpointID            string
	NetworkNameSpace         string `json:",omitempty"`
	ContainerID              string
	PODName                  string `json:",omitempty"`
	PODNameSpace             string `json:",omitempty"`
	InfraVnetAddressSpace    string `json:",omitempty"`
	NetNs                    string `json:",omitempty"`
	NetworkID                string
}

// EndpointInfo contains read-only information about an endpoint.
type EndpointInfo struct {
	Id                       string
	ContainerID              string
	NetNsPath                string
	IfName                   string
	SandboxKey               string
	IfIndex                  int
	MacAddress               net.HardwareAddr
	DNS                      DNSInfo
	IPAddresses              []net.IPNet
	InfraVnetIP              net.IPNet
	Routes                   []RouteInfo
	Policies                 []policy.Policy
	Gateways                 []net.IP
	EnableSnatOnHost         bool
	EnableInfraVnet          bool
	EnableMultiTenancy       bool
	AllowInboundFromHostToNC bool
	AllowInboundFromNCToHost bool
	HostNCApipaEndpointID            string
	PODName                  string
	PODNameSpace             string
	Data                     map[string]interface{}
	InfraVnetAddressSpace    string
	SkipHotAttachEp          bool
	NetworkID                string
}

// RouteInfo contains information about an IP route.
type RouteInfo struct {
	Dst      net.IPNet
	Src      net.IP
	Gw       net.IP
	Protocol int
	DevName  string
	Scope    int
}
