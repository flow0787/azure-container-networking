// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package network

import (
	"encoding/json"
	"fmt"
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

// UseHnsV2 indicates whether to use HNSv1 or HNSv2
func UseHnsV2(netNs string) (bool, error) {
	// Check if the netNs is a valid GUID to decide on HNSv1 or HNSv2
	useHnsV2 := false
	var err error
	if _, err = uuid.Parse(netNs); err == nil {
		useHnsV2 = true
		if err = hcn.V2ApiSupported(); err != nil {
			log.Printf("HNSV2 is not supported on this windows platform")
		}
	}

	return useHnsV2, err
}

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

// configureHcnEndpoint configures hcn endpoint for creation
func (nm *networkManager) configureHcnNetwork(nwInfo *NetworkInfo, extIf *externalInterface) (*hcn.HostComputeNetwork, error) {
	// Initialize HNS network.
	hcnNetwork := &hcn.HostComputeNetwork{
		Name: nwInfo.Id,
		Dns: hcn.Dns{
			Domain:     nwInfo.DNS.Suffix,
			ServerList: nwInfo.DNS.Servers,
		},
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
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

		hcnNetwork.Policies = append(hcnNetwork.Policies, netAdapterNamePolicy)
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
		hcnNetwork.Type = hcn.L2Bridge
	case opModeTunnel:
		hcnNetwork.Type = hcn.L2Tunnel
	default:
		return nil, errNetworkModeInvalid
	}

	// Populate subnets.
	for _, subnet := range nwInfo.Subnets {
		hnsSubnet := hcn.Subnet{
			IpAddressPrefix: subnet.Prefix.String(),
			Routes: []hcn.Route{
				hcn.Route{
					NextHop:           subnet.Gateway.String(),
					DestinationPrefix: "0.0.0.0/0",
				},
			},
		}

		// Set the subnet policy
		if vlanid > 0 {
			hnsSubnet.Policies = append(hnsSubnet.Policies, subnetPolicy)
		}

		hcnNetwork.Ipams[0].Subnets = append(hcnNetwork.Ipams[0].Subnets, hnsSubnet)
	}

	return hcnNetwork, nil
}

// newNetworkImplHnsV2 creates a new container network for HNSv2.
func (nm *networkManager) newNetworkImplHnsV2(nwInfo *NetworkInfo, extIf *externalInterface) (*network, error) {
	// Do this only if there hostToCont / ContToHost is set
	// if hostToCont / ContToHost
	/*
		{
			apipaNw, err := nm.createApipaNw()
			if err != nil {
				err := fmt.Errorf("Failed to create APIPA bridge network for host to container connectivity due to error: %v", err)
				log.Errorf("[net] %s", err.Error())
				return nil, err
			}

			log.Printf("[net] Successfully setup APIPA bridge network for host to container connectivity: %+v", apipaNw)
		}
	*/

	hcnNetwork, err := nm.configureHcnNetwork(nwInfo, extIf)
	if err != nil {
		log.Printf("[net] Failed to configure hcn network due to error: %v", err)
		return nil, err
	}

	// Create the HNS network.
	log.Printf("[net] Creating hcn network: %+v", hcnNetwork)
	hnsResponse, err := hcnNetwork.Create()

	if err != nil {
		return nil, fmt.Errorf("Failed to create hcn network: %s due to error: %v", hcnNetwork.Name, err)
	}

	log.Printf("[net] Successfully created hcn network with response: %+v", hnsResponse)

	var vlanid int
	opt, _ := nwInfo.Options[genericData].(map[string]interface{})
	if opt != nil && opt[VlanIDKey] != nil {
		vlanID, _ := strconv.ParseInt(opt[VlanIDKey].(string), 10, 32)
		vlanid = (int)(vlanID)
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

	return nw, nil
}

/*
// configureHcnEndpoint configures hcn endpoint for creation
func (nm *networkManager) configureApipaNetwork() (*hcn.HostComputeNetwork, error) {
	// Initialize HNS network.
	hcnNetwork := &hcn.HostComputeNetwork{
		Name: "secondary-nw",
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
	}

	// TODO: How to get this string from the created loopback adapter?
	netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy("Ethernet 6")
	if err != nil {
		log.Printf("[net] Failed to serialize network adapter policy due to error: %v", err)
		return nil, err
	}

	hcnNetwork.Policies = append(hcnNetwork.Policies, netAdapterNamePolicy)

	// Set hcn subnet policy
	var vlanid int
	vlanid = 0

	var subnetPolicy []byte

	hcnNetwork.Type = hcn.L2Bridge

	// Populate subnets.
	hnsSubnet := hcn.Subnet{
		IpAddressPrefix: "169.254.0.0/16",
		Routes: []hcn.Route{
			hcn.Route{
				NextHop:           "169.254.0.2",
				DestinationPrefix: "0.0.0.0/0",
			},
		},
	}

	// Set the subnet policy
	if vlanid > 0 {
		hnsSubnet.Policies = append(hnsSubnet.Policies, subnetPolicy)
	}

	hcnNetwork.Ipams[0].Subnets = append(hcnNetwork.Ipams[0].Subnets, hnsSubnet)

	return hcnNetwork, nil
}
*/

/*
// createApipaNw creates a new container network for HNSv2.
func (nm *networkManager) createApipaNw() (*hcn.HostComputeNetwork, error) {
	var hcnNetwork *hcn.HostComputeNetwork
	var err error
	if hcnNetwork, err = hcn.GetNetworkByName("secondary-nw"); err == nil {
		log.Printf("[net] Found existing APIPA network: %+v", hcnNetwork)
		return nil, nil
	}

	hcnNetwork, err = nm.configureApipaNetwork()
	if err != nil {
		log.Printf("[net] Failed to configure hcn network due to error: %v", err)
		return nil, err
	}

	// Create the HNS network.
	log.Printf("[net] Creating temp hcn network: %+v", hcnNetwork)
	hnsResponse, err := hcnNetwork.Create()

	if err != nil {
		log.Printf("[net] Failed to create temp hcn network due to error: %v", err)
		return nil, fmt.Errorf("Failed to create hcn network: %s due to error: %v", hcnNetwork.Name, err)
	}

	log.Printf("[net] Successfully created temp hcn network with response: %+v", hnsResponse)

	return hnsResponse, nil
}
*/

// NewNetworkImpl creates a new container network.
func (nm *networkManager) newNetworkImpl(nwInfo *NetworkInfo, extIf *externalInterface) (*network, error) {
	if useHnsV2, err := UseHnsV2(nwInfo.NetNs); useHnsV2 {
		if err != nil {
			return nil, err
		}

		return nm.newNetworkImplHnsV2(nwInfo, extIf)
	}

	return nm.newNetworkImplHnsV1(nwInfo, extIf)
}

// DeleteNetworkImpl deletes an existing container network.
func (nm *networkManager) deleteNetworkImpl(nw *network) error {
	if useHnsV2, err := UseHnsV2(nw.NetNs); useHnsV2 {
		if err != nil {
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
	var hcnNetwork *hcn.HostComputeNetwork
	var err error
	log.Printf("[net] Deleting hcn network with id: %s", nw.HnsId)

	if hcnNetwork, err = hcn.GetNetworkByID(nw.HnsId); err != nil {
		return fmt.Errorf("Failed to get hcn network with id: %s due to err: %v", nw.HnsId, err)
	}

	if err = hcnNetwork.Delete(); err != nil {
		return fmt.Errorf("Failed to delete hcn network: %s due to error: %v", nw.HnsId, err)
	}

	log.Printf("[net] Successfully deleted hcn network with id: %s", nw.HnsId)

	return err
}

func getNetworkInfoImpl(nwInfo *NetworkInfo, nw *network) {
}
