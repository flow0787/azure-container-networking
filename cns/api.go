// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package cns

import (
	"encoding/json"
	//"github.com/Azure/azure-container-networking/network"
	models "github.com/Azure/azure-container-networking/network/models"
)

// Container Network Service remote API Contract
const (
	SetEnvironmentPath            = "/network/environment"
	CreateNetworkPath             = "/network/create"
	DeleteNetworkPath             = "/network/delete"
	CreateHnsNetworkPath          = "/network/hns/create"
	DeleteHnsNetworkPath          = "/network/hns/delete"
	ReserveIPAddressPath          = "/network/ip/reserve"
	ReleaseIPAddressPath          = "/network/ip/release"
	GetHostLocalIPPath            = "/network/ip/hostlocal"
	GetIPAddressUtilizationPath   = "/network/ip/utilization"
	GetUnhealthyIPAddressesPath   = "/network/ipaddresses/unhealthy"
	GetHealthReportPath           = "/network/health"
	NumberOfCPUCoresPath          = "/hostcpucores"
	CreateHostNCApipaEndpointPath = "/network/createhostncapipaendpoint"
	DeleteHostNCApipaEndpointPath = "/network/deletehostncapipaendpoint"
	CreateNewNetworkPath          = "/network/createnewnetwork"
	DeleteNewNetworkPath          = "/network/deletenewnetwork"
	CreateNewEndpointPath         = "/network/createnewendpoint"
	DeleteNewEndpointPath         = "/network/deletenewendpoint"
	V1Prefix                      = "/v0.1"
	V2Prefix                      = "/v0.2"

	OptOrchContext = "OrchestratorContext"
	OptNCID        = "NCID"
)

/*
// DNSInfo contains DNS information for a container network or endpoint.
type DNSInfo struct {
	Suffix  string
	Servers []string
	Options []string
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

// ExternalInterface is a host network interface that bridges containers to external networks.
type externalInterface struct {
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
*/

// SetEnvironmentRequest describes the Request to set the environment in CNS.
type SetEnvironmentRequest struct {
	Location    string
	NetworkType string
}

// OverlayConfiguration describes configuration for all the nodes that are part of overlay.
type OverlayConfiguration struct {
	NodeCount     int
	LocalNodeIP   string
	OverlaySubent Subnet
	NodeConfig    []NodeConfiguration
}

// CreateNetworkRequest describes request to create the network.
type CreateNetworkRequest struct {
	NetworkName          string
	OverlayConfiguration OverlayConfiguration
	Options              map[string]interface{}
}

// DeleteNetworkRequest describes request to delete the network.
type DeleteNetworkRequest struct {
	NetworkName string
}

// CreateHnsNetworkRequest describes request to create the HNS network.
type CreateHnsNetworkRequest struct {
	NetworkName          string
	NetworkType          string
	NetworkAdapterName   string            `json:",omitempty"`
	SourceMac            string            `json:",omitempty"`
	Policies             []json.RawMessage `json:",omitempty"`
	MacPools             []MacPool         `json:",omitempty"`
	Subnets              []SubnetInfo
	DNSSuffix            string `json:",omitempty"`
	DNSServerList        string `json:",omitempty"`
	DNSServerCompartment uint32 `json:",omitempty"`
	ManagementIP         string `json:",omitempty"`
	AutomaticDNS         bool   `json:",omitempty"`
}

// SubnetInfo is assoicated with HNS network and represents a list
// of subnets available to the network
type SubnetInfo struct {
	AddressPrefix  string
	GatewayAddress string
	Policies       []json.RawMessage `json:",omitempty"`
}

// MacPool is assoicated with HNS  network and represents a list
// of macaddresses available to the network
type MacPool struct {
	StartMacAddress string
	EndMacAddress   string
}

// DeleteHnsNetworkRequest describes request to delete the HNS network.
type DeleteHnsNetworkRequest struct {
	NetworkName string
}

// ReserveIPAddressRequest describes request to reserve an IP Address
type ReserveIPAddressRequest struct {
	ReservationID string
}

// ReserveIPAddressResponse describes response to reserve an IP address.
type ReserveIPAddressResponse struct {
	Response  Response
	IPAddress string
}

// ReleaseIPAddressRequest describes request to release an IP Address.
type ReleaseIPAddressRequest struct {
	ReservationID string
}

// IPAddressesUtilizationResponse describes response for ip address utilization.
type IPAddressesUtilizationResponse struct {
	Response  Response
	Available int
	Reserved  int
	Unhealthy int
}

// GetIPAddressesResponse describes response containing requested ip addresses.
type GetIPAddressesResponse struct {
	Response    Response
	IPAddresses []string
}

// HostLocalIPAddressResponse describes reponse that returns the host local IP Address.
type HostLocalIPAddressResponse struct {
	Response  Response
	IPAddress string
}

// Subnet contains the ip address and the number of bits in prefix.
type Subnet struct {
	IPAddress    string
	PrefixLength int
}

// NodeConfiguration describes confguration for a node in overlay network.
type NodeConfiguration struct {
	NodeIP     string
	NodeID     string
	NodeSubnet Subnet
}

// Response describes generic response from CNS.
type Response struct {
	ReturnCode int
	Message    string
}

// NumOfCPUCoresResponse describes num of cpu cores present on host.
type NumOfCPUCoresResponse struct {
	Response      Response
	NumOfCPUCores int
}

// OptionMap describes generic options that can be passed to CNS.
type OptionMap map[string]interface{}

// Response to a failed request.
type errorResponse struct {
	Err string
}

// CreateNewNetworkRequest describes request to create new network.
type CreateNewNetworkRequest struct {
	NetworkInfo       models.NetworkInfo
	ExternalInterface models.ExternalInterface
}

// CreateNewEndpointRequest describes request to create new endpoint.
type CreateNewEndpointRequest struct {
	EndpointInfo models.EndpointInfo
}

// CreateHostNCApipaEndpointRequest describes request for create apipa endpoint
// for host container connectivity for the given network container
type CreateHostNCApipaEndpointRequest struct {
	NetworkContainerID string
	//OrchestratorContext json.RawMessage
}

// CreateHostNCApipaEndpointResponse describes response for create apipa endpoint request
// for host container connectivity.
type CreateHostNCApipaEndpointResponse struct {
	Response   Response
	EndpointID string
}

// DeleteHostNCApipaEndpointRequest describes request for deleting apipa endpoint created
// for host NC connectivity.
type DeleteHostNCApipaEndpointRequest struct {
	EndpointID string
}

// DeleteHostNCApipaEndpointResponse describes response for delete host NC apipa endpoint request.
type DeleteHostNCApipaEndpointResponse struct {
	Response Response
}
