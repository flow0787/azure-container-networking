// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package network

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/google/uuid"
)

const (
	// HNS network types.
	hnsL2bridge      = "l2bridge"
	hnsL2tunnel      = "l2tunnel"
	CnetAddressSpace = "cnetAddressSpace"
)

// Windows implementation of route.
type route interface{}

// newNetworkImplHnsV1 creates a new container network for HNSv1.
func (nm *networkManager) newNetworkImplHnsV1(nwInfo *NetworkInfo, extIf *externalInterface) (*network, error) {
	var vlanid int
	networkAdapterName := extIf.Name
	// FixMe: Find a better way to check if a nic that is selected is not part of a vSwitch
	if strings.HasPrefix(networkAdapterName, "vEthernet") {
		networkAdapterName = ""
	}
	// Initialize HNS network.
	hnsNetwork := &hcsshim.HNSNetwork{
		Name:               nwInfo.Id,
		NetworkAdapterName: networkAdapterName,
		DNSServerList:      strings.Join(nwInfo.DNS.Servers, ","),
		Policies:           policy.SerializePolicies(policy.NetworkPolicy, nwInfo.Policies, nil),
	}

	// Set the VLAN and OutboundNAT policies
	opt, _ := nwInfo.Options[genericData].(map[string]interface{})
	if opt != nil && opt[VlanIDKey] != nil {
		vlanPolicy := hcsshim.VlanPolicy{
			Type: "VLAN",
		}
		vlanID, _ := strconv.ParseUint(opt[VlanIDKey].(string), 10, 32)
		vlanPolicy.VLAN = uint(vlanID)

		serializedVlanPolicy, _ := json.Marshal(vlanPolicy)
		hnsNetwork.Policies = append(hnsNetwork.Policies, serializedVlanPolicy)

		vlanid = (int)(vlanPolicy.VLAN)
	}

	// Set network mode.
	switch nwInfo.Mode {
	case opModeBridge:
		hnsNetwork.Type = hnsL2bridge
	case opModeTunnel:
		hnsNetwork.Type = hnsL2tunnel
	default:
		return nil, errNetworkModeInvalid
	}

	// Populate subnets.
	for _, subnet := range nwInfo.Subnets {
		hnsSubnet := hcsshim.Subnet{
			AddressPrefix:  subnet.Prefix.String(),
			GatewayAddress: subnet.Gateway.String(),
		}

		hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)
	}

	// Marshal the request.
	buffer, err := json.Marshal(hnsNetwork)
	if err != nil {
		return nil, err
	}
	hnsRequest := string(buffer)

	// Create the HNS network.
	log.Printf("[net] HNSNetworkRequest POST request:%+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
	log.Printf("[net] HNSNetworkRequest POST response:%+v err:%v.", hnsResponse, err)
	if err != nil {
		return nil, err
	}

	// Create the network object.
	nw := &network{
		Id:               nwInfo.Id,
		HnsId:            hnsResponse.Id,
		Mode:             nwInfo.Mode,
		Endpoints:        make(map[string]*endpoint),
		extIf:            extIf,
		VlanId:           vlanid,
		EnableSnatOnHost: nwInfo.EnableSnatOnHost,
		NetNs:            nwInfo.NetNs,
	}

	globals, err := hcsshim.GetHNSGlobals()
	if err != nil || globals.Version.Major <= hcsshim.HNSVersion1803.Major {
		// err would be not nil for windows 1709 & below
		// Sleep for 10 seconds as a workaround for windows 1803 & below
		// This is done only when the network is created.
		time.Sleep(time.Duration(10) * time.Second)
	}

	return nw, nil
}

// newNetworkImplHnsV2 creates a new container network for HNSv2.
func (nm *networkManager) newNetworkImplHnsV2(nwInfo *NetworkInfo, extIf *externalInterface) (*network, error) {
	// Initialize HNS network.
	hnsNetwork := &hcn.HostComputeNetwork{
		Name: nwInfo.Id,
		Dns: hcn.Dns{
			Domain:     nwInfo.DNS.Suffix,
			ServerList: nwInfo.DNS.Servers,
		},
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: "Static",
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
	}

	// Set hcn network adaptor name policy
	// FixMe: Find a better way to check if a nic that is selected is not part of a vSwitch
	if !strings.HasPrefix(extIf.Name, "vEthernet") {
		netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy(extIf.Name)
		if err != nil {
			log.Printf("[net] Failed to serialize network adapter policy due to error: %v", err)
			return nil, err
		}

		hnsNetwork.Policies = append(hnsNetwork.Policies, netAdapterNamePolicy)
	}

	// Set hcn subnet policy
	var vlanid int
	var subnetPolicy []byte
	opt, _ := nwInfo.Options[genericData].(map[string]interface{})
	if opt != nil && opt[VlanIDKey] != nil {
		var err error
		vlanID, _ := strconv.ParseUint(opt[VlanIDKey].(string), 10, 32)
		subnetPolicy, err = policy.SerializeHcnSubnetVlanPolicy((uint32)(vlanID))
		if err != nil {
			log.Printf("[net] Failed to serialize subnet vlan policy due to error: %v", err)
			return nil, err
		}

		vlanid = (int)(vlanID)
	}

	// Set network mode.
	switch nwInfo.Mode {
	case opModeBridge:
		hnsNetwork.Type = hcn.L2Bridge
	case opModeTunnel:
		hnsNetwork.Type = hcn.L2Tunnel
	default:
		return nil, errNetworkModeInvalid
	}

	// Populate subnets.
	for _, subnet := range nwInfo.Subnets {
		hnsSubnet := hcn.Subnet{
			IpAddressPrefix: subnet.Prefix.String(),
			Routes: []hcn.Route{
				hcn.Route{
					NextHop: subnet.Gateway.String(),
					DestinationPrefix: "0.0.0.0/0",
				},
			},
		}

		// Set the subnet policy
		if vlanid > 0 {
			hnsSubnet.Policies = append(hnsSubnet.Policies, subnetPolicy)
		}

		hnsNetwork.Ipams[0].Subnets = append(hnsNetwork.Ipams[0].Subnets, hnsSubnet)
	}

	// Create the HNS network.
	log.Printf("[net] HostComputeNetwork Create: %+v", hnsNetwork)
	hnsResponse, err := hnsNetwork.Create()
	log.Printf("[net] HostComputeNetwork Create response: %+v err: %v.", hnsResponse, err)

	if err != nil {
		return nil, err
	}

	// Create the network object.
	nw := &network{
		Id:               nwInfo.Id,
		HnsId:            hnsResponse.Id,
		Mode:             nwInfo.Mode,
		Endpoints:        make(map[string]*endpoint),
		extIf:            extIf,
		VlanId:           vlanid,
		EnableSnatOnHost: nwInfo.EnableSnatOnHost,
		NetNs:            nwInfo.NetNs,
	}

	globals, err := hcn.GetGlobals()
	if err != nil || globals.Version.Major <= hcn.HNSVersion1803.Major {
		// err would be not nil for windows 1709 & below
		// Sleep for 10 seconds as a workaround for windows 1803 & below
		// This is done only when the network is created.
		time.Sleep(time.Duration(10) * time.Second)
	}

	return nw, nil
}

// NewNetworkImpl creates a new container network.
func (nm *networkManager) newNetworkImpl(nwInfo *NetworkInfo, extIf *externalInterface) (*network, error) {
	// Check if the netNs is a valid GUID to decide on HNSv1 or HNSv2
	if _, err := uuid.Parse(nwInfo.NetNs); err == nil {
		if err = hcn.V2ApiSupported(); err != nil {
			log.Printf("HNSV2 is not supported on this windows platform")
			return nil, err
		}

		return nm.newNetworkImplHnsV2(nwInfo, extIf)
	}

	return nm.newNetworkImplHnsV1(nwInfo, extIf)
}

// DeleteNetworkImpl deletes an existing container network.
func (nm *networkManager) deleteNetworkImpl(nw *network) error {
	// Delete the HNS network.
	// Check if the netNs is a valid GUID to decide on HNSv1 or HNSv2
	if _, err := uuid.Parse(nw.NetNs); err == nil {
		if err = hcn.V2ApiSupported(); err != nil {
			log.Printf("HNSV2 is not supported on this windows platform")
			return err
		}

		return nm.deleteNetworkImplHnsV2(nw)
	}

	return nm.deleteNetworkImplHnsV1(nw)
}

// DeleteNetworkImplHnsV1 deletes an existing container network using HnsV1.
func (nm *networkManager) deleteNetworkImplHnsV1(nw *network) error {
	log.Printf("[net] HNSNetworkRequest DELETE id:%v", nw.HnsId)
	hnsResponse, err := hcsshim.HNSNetworkRequest("DELETE", nw.HnsId, "")
	log.Printf("[net] HNSNetworkRequest DELETE response:%+v err:%v.", hnsResponse, err)

	return err
}

// DeleteNetworkImplHnsV2 deletes an existing container network using HnsV2.
func (nm *networkManager) deleteNetworkImplHnsV2(nw *network) error {
	var hnsNetwork *hcn.HostComputeNetwork
	var err error
	log.Printf("[net] HostComputeNetwork DELETE id:%v", nw.HnsId)
	if hnsNetwork, err = hcn.GetNetworkByID(nw.HnsId); err == nil {
		err = hnsNetwork.Delete()
	}

	log.Printf("[net] HostComputeNetwork DELETE err:%v.", err)

	return err
}

func getNetworkInfoImpl(nwInfo *NetworkInfo, nw *network) {
}
