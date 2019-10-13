// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package network

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/Azure/azure-container-networking/cns/cnsclient"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

const (
	// hcnSchemaVersionMajor indicates major version number for hcn schema
	hcnSchemaVersionMajor = 2

	// hcnSchemaVersionMinor indicates minor version number for hcn schema
	hcnSchemaVersionMinor = 0

	// hcnIpamTypeStatic indicates the static type of ipam
	hcnIpamTypeStatic = "Static"

	// HostNCApipaNetworkName indicates the name of the apipa network used for host container connectivity
	HostNCApipaNetworkName = "host-nc-apipa-network"
)

// HotAttachEndpoint is a wrapper of hcsshim's HotAttachEndpoint.
func (endpoint *EndpointInfo) HotAttachEndpoint(containerID string) error {
	return hcsshim.HotAttachEndpoint(containerID, endpoint.Id)
}

// ConstructEndpointID constructs endpoint name from netNsPath.
func ConstructEndpointID(containerID string, netNsPath string, ifName string) (string, string) {
	if len(containerID) > 8 {
		containerID = containerID[:8]
	}

	infraEpName, workloadEpName := "", ""

	splits := strings.Split(netNsPath, ":")
	if len(splits) == 2 {
		// For workload containers, we extract its linking infrastructure container ID.
		if len(splits[1]) > 8 {
			splits[1] = splits[1][:8]
		}
		infraEpName = splits[1] + "-" + ifName
		workloadEpName = containerID + "-" + ifName
	} else {
		// For infrastructure containers, we use its container ID directly.
		infraEpName = containerID + "-" + ifName
	}

	return infraEpName, workloadEpName
}

// newEndpointImpl creates a new endpoint in the network.
func (nw *network) newEndpointImpl(epInfo *EndpointInfo) (*endpoint, error) {
	if useHnsV2, err := UseHnsV2(epInfo.NetNsPath); useHnsV2 {
		if err != nil {
			return nil, err
		}

		return nw.newEndpointImplHnsV2(epInfo)
	}

	return nw.newEndpointImplHnsV1(epInfo)
}

// newEndpointImplHnsV1 creates a new endpoint in the network using HnsV1
func (nw *network) newEndpointImplHnsV1(epInfo *EndpointInfo) (*endpoint, error) {
	var vlanid int

	if epInfo.Data != nil {
		if _, ok := epInfo.Data[VlanIDKey]; ok {
			vlanid = epInfo.Data[VlanIDKey].(int)
		}
	}

	// Get Infrastructure containerID. Handle ADD calls for workload container.
	var err error
	infraEpName, _ := ConstructEndpointID(epInfo.ContainerID, epInfo.NetNsPath, epInfo.IfName)
	hnsEndpoint := &hcsshim.HNSEndpoint{
		Name:           infraEpName,
		VirtualNetwork: nw.HnsId,
		DNSSuffix:      epInfo.DNS.Suffix,
		DNSServerList:  strings.Join(epInfo.DNS.Servers, ","),
		Policies:       policy.SerializePolicies(policy.EndpointPolicy, epInfo.Policies, epInfo.Data),
	}

	// HNS currently supports only one IP address per endpoint.
	if epInfo.IPAddresses != nil {
		hnsEndpoint.IPAddress = epInfo.IPAddresses[0].IP
		pl, _ := epInfo.IPAddresses[0].Mask.Size()
		hnsEndpoint.PrefixLength = uint8(pl)
	}

	// Marshal the request.
	buffer, err := json.Marshal(hnsEndpoint)
	if err != nil {
		return nil, err
	}
	hnsRequest := string(buffer)

	// Create the HNS endpoint.
	log.Printf("[net] HNSEndpointRequest POST request:%+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSEndpointRequest("POST", "", hnsRequest)
	log.Printf("[net] HNSEndpointRequest POST response:%+v err:%v.", hnsResponse, err)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			log.Printf("[net] HNSEndpointRequest DELETE id:%v", hnsResponse.Id)
			hnsResponse, err := hcsshim.HNSEndpointRequest("DELETE", hnsResponse.Id, "")
			log.Printf("[net] HNSEndpointRequest DELETE response:%+v err:%v.", hnsResponse, err)
		}
	}()

	if epInfo.SkipHotAttachEp {
		log.Printf("[net] Skipping attaching the endpoint %v to container %v.",
			hnsResponse.Id, epInfo.ContainerID)
	} else {
		// Attach the endpoint.
		log.Printf("[net] Attaching endpoint %v to container %v.", hnsResponse.Id, epInfo.ContainerID)
		err = hcsshim.HotAttachEndpoint(epInfo.ContainerID, hnsResponse.Id)
		if err != nil {
			log.Printf("[net] Failed to attach endpoint: %v.", err)
			return nil, err
		}
	}

	// Create the endpoint object.
	ep := &endpoint{
		Id:               infraEpName,
		HnsId:            hnsResponse.Id,
		SandboxKey:       epInfo.ContainerID,
		IfName:           epInfo.IfName,
		IPAddresses:      epInfo.IPAddresses,
		Gateways:         []net.IP{net.ParseIP(hnsResponse.GatewayAddress)},
		DNS:              epInfo.DNS,
		VlanID:           vlanid,
		EnableSnatOnHost: epInfo.EnableSnatOnHost,
		NetNs:            epInfo.NetNsPath,
	}

	for _, route := range epInfo.Routes {
		ep.Routes = append(ep.Routes, route)
	}

	ep.MacAddress, _ = net.ParseMAC(hnsResponse.MacAddress)

	return ep, nil
}

// configureHcnEndpoint configures hcn endpoint for creation
func (nw *network) configureHcnEndpoint(epInfo *EndpointInfo) (*hcn.HostComputeEndpoint, error) {
	infraEpName, _ := ConstructEndpointID(epInfo.ContainerID, epInfo.NetNsPath, epInfo.IfName)

	hcnEndpoint := &hcn.HostComputeEndpoint{
		Name:               infraEpName,
		HostComputeNetwork: nw.HnsId,
		Dns: hcn.Dns{
			Search:     strings.Split(epInfo.DNS.Suffix, ","),
			ServerList: epInfo.DNS.Servers,
			Options:    epInfo.DNS.Options,
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
		MacAddress: epInfo.MacAddress.String(),
	}

	if endpointPolicies, err := policy.GetHcnEndpointPolicies(false, policy.EndpointPolicy, epInfo.Policies, epInfo.Data); err == nil {
		for _, epPolicy := range endpointPolicies {
			hcnEndpoint.Policies = append(hcnEndpoint.Policies, epPolicy)
		}
	} else {
		log.Printf("[net] Failed to get endpoint policies due to error: %v", err)
		return nil, err
	}

	for _, route := range epInfo.Routes {
		hcnRoute := hcn.Route{
			NextHop:           route.Gw.String(),
			DestinationPrefix: route.Dst.String(),
		}

		hcnEndpoint.Routes = append(hcnEndpoint.Routes, hcnRoute)
	}

	for _, ipAddress := range epInfo.IPAddresses {
		prefixLength, _ := ipAddress.Mask.Size()
		ipConfiguration := hcn.IpConfig{
			IpAddress:    ipAddress.IP.String(),
			PrefixLength: uint8(prefixLength),
		}

		hcnEndpoint.IpConfigurations = append(hcnEndpoint.IpConfigurations, ipConfiguration)
	}

	return hcnEndpoint, nil
}

// configureApipaEndpoint configures hcn endpoint for creation
func (nw *network) configureApipaEndpoint(epInfo *EndpointInfo) (*hcn.HostComputeEndpoint, error) {
	//infraEpName, _ := ConstructEndpointID(epInfo.ContainerID, epInfo.NetNsPath, epInfo.IfName)
	var hcnNetwork *hcn.HostComputeNetwork
	var err error
	if hcnNetwork, err = hcn.GetNetworkByName("secondary-nw"); err != nil {
		log.Printf("[net] Failed to get temp nw due to error: %v", err)
		return nil, fmt.Errorf("Failed to get hcn network with id: %s due to err: %v", nw.HnsId, err)
	}

	name := "secondaryepwin"

	hcnEndpoint := &hcn.HostComputeEndpoint{
		Name:               name,
		HostComputeNetwork: hcnNetwork.Id,
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
	}

	// TODO: below code can be handled by passing the context to the CNS and CNS looking up localIP from the CNS config
	var localIP string
	if epInfo.Data != nil {
		if localIPData, ok := epInfo.Data[LocalIPKey]; ok {
			localIP = localIPData.(string)
		}
	}

	/********************************************************************************************************/
	// Add ICMP ACLs
	{
		// Add endpoint ACL for preventing the comm to other apipa
		aclOutBlockAll := hcn.AclPolicySetting{
			Protocols:      "1",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeOut,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err := json.Marshal(aclOutBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy := hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "1",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclOutAllowToHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInBlockAll := hcn.AclPolicySetting{
			Protocols:      "1",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeIn,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err = json.Marshal(aclInBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "1",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclInAllowFromHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)
	}

	// Add TCP ACLs
	{
		// Add endpoint ACL for preventing the comm to other apipa
		aclOutBlockAll := hcn.AclPolicySetting{
			Protocols:      "6",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeOut,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err := json.Marshal(aclOutBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy := hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "6",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclOutAllowToHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInBlockAll := hcn.AclPolicySetting{
			Protocols:      "6",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeIn,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err = json.Marshal(aclInBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "6",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclInAllowFromHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)
	}

	// Add UDP ACLs
	{
		// Add endpoint ACL for preventing the comm to other apipa
		aclOutBlockAll := hcn.AclPolicySetting{
			Protocols:      "17",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeOut,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err := json.Marshal(aclOutBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy := hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "17",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclOutAllowToHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInBlockAll := hcn.AclPolicySetting{
			Protocols:      "17",
			Action:         hcn.ActionTypeBlock,
			Direction:      hcn.DirectionTypeIn,
			LocalAddresses: localIP,
			RuleType:       hcn.RuleTypeSwitch,
			Priority:       2000,
		}

		rawJSON, err = json.Marshal(aclInBlockAll)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "17",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: "169.254.0.2",
			RuleType:        hcn.RuleTypeSwitch,
			Priority:        200,
		}

		rawJSON, err = json.Marshal(aclInAllowFromHostOnly)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal the endpoint ACL")
		}

		endpointPolicy = hcn.EndpointPolicy{
			Type:     hcn.ACL,
			Settings: rawJSON,
		}

		hcnEndpoint.Policies = append(hcnEndpoint.Policies, endpointPolicy)
	}
	/********************************************************************************************************/

	nexthop := "169.254.0.2"
	hcnRoute := hcn.Route{
		NextHop:           nexthop,
		DestinationPrefix: "0.0.0.0/0",
	}

	hcnEndpoint.Routes = append(hcnEndpoint.Routes, hcnRoute)

	ipConfiguration := hcn.IpConfig{
		IpAddress:    localIP,
		PrefixLength: 16, // TODO: this should come from the cns config
	}

	hcnEndpoint.IpConfigurations = append(hcnEndpoint.IpConfigurations, ipConfiguration)

	return hcnEndpoint, nil
}

func (nw *network) deleteHostNCApipaEndpoint(endpointID string) error {
	// TODO: cnsclient shouldn't be here. Need to move and encap this somewhere else.
	cnsClient, err := cnsclient.NewCnsClient("") //TODO: Need to pass the CNS url from nwCfg
	if err != nil {
		log.Errorf("Initializing CNS client error %v", err)
		return err
	}

	log.Printf("[net] Deleting apipa hcn endpoint with id: %s", endpointID)
	err = cnsClient.DeleteHostNCApipaEndpoint(endpointID)
	log.Printf("[net] Completed hcn endpoint deletion for id: %s with error: %v", endpointID, err)

	return nil
}

func (nw *network) createHostNCApipaEndpoint(epInfo *EndpointInfo) error {
	var (
		err                   error
		cnsClient             *cnsclient.CNSClient
		hostNCApipaEndpointID string
		//hostNCApipaNetwork    *hcn.HostComputeNetwork
		namespace *hcn.HostComputeNamespace
	)

	if namespace, err = hcn.GetNamespaceByID(epInfo.NetNsPath); err != nil {
		return fmt.Errorf("Failed to retrieve namespace with GetNamespaceByID for NetNsPath: %s"+
			" due to error: %v", epInfo.NetNsPath, err)
	}

	// TODO: This should be changed to GetCnsClient()
	cnsClient, err = cnsclient.NewCnsClient("") //TODO: Need to pass the CNS url from nwCfg
	if err != nil {
		log.Errorf("Initializing CNS client error %v", err)
		return err // upfate this to meaningful error
	}

	log.Printf("[Azure CNS] Creating endpoint for host container connectivity")

	if hostNCApipaEndpointID, err =
		cnsClient.CreateHostNCApipaEndpoint(epInfo.NetworkContainerID /*epInfo.PODName, epInfo.PODNameSpace*/); err != nil {
		return err
	}

	defer func() {
		if err != nil {
			log.Printf("[net] Deleting hcn endpoint with id: %s", hostNCApipaEndpointID)
			// TODO: when this becomes generic, localIP can be passed to delete the endpoint
			err = cnsClient.DeleteHostNCApipaEndpoint(hostNCApipaEndpointID)
			log.Printf("[net] Completed hcn endpoint deletion for id: %s with error: %v", hostNCApipaEndpointID, err)
		}
	}()

	if err = hcn.AddNamespaceEndpoint(namespace.Id, hostNCApipaEndpointID); err != nil {
		return fmt.Errorf("[net] Failed to add HostNCApipaEndpoint: %s to namespace: %s due to error: %v",
			hostNCApipaEndpointID, namespace.Id, err)
	}

	epInfo.HostNCApipaEndpointID = hostNCApipaEndpointID

	return nil
}

// newEndpointImplHnsV2 creates a new endpoint in the network using HnsV2
func (nw *network) newEndpointImplHnsV2(epInfo *EndpointInfo) (*endpoint, error) {
	hcnEndpoint, err := nw.configureHcnEndpoint(epInfo)
	if err != nil {
		log.Printf("[net] Failed to configure hcn endpoint due to error: %v", err)
		return nil, err
	}

	// Create the HCN endpoint.
	log.Printf("[net] Creating hcn endpoint: %+v", hcnEndpoint)
	hnsResponse, err := hcnEndpoint.Create()
	if err != nil {
		return nil, fmt.Errorf("Failed to create endpoint: %s due to error: %v", hcnEndpoint.Name, err)
	}

	log.Printf("[net] Successfully created hcn endpoint with response: %+v", hnsResponse)

	defer func() {
		if err != nil {
			log.Printf("[net] Deleting hcn endpoint with id: %s", hnsResponse.Id)
			err = hnsResponse.Delete()
			log.Printf("[net] Completed hcn endpoint deletion for id: %s with error: %v", hnsResponse.Id, err)
		}
	}()

	var namespace *hcn.HostComputeNamespace
	if namespace, err = hcn.GetNamespaceByID(epInfo.NetNsPath); err != nil {
		return nil, fmt.Errorf("Failed to get hcn namespace: %s due to error: %v", epInfo.NetNsPath, err)
	}

	if err = hcn.AddNamespaceEndpoint(namespace.Id, hnsResponse.Id); err != nil {
		return nil, fmt.Errorf("[net] Failed to add endpoint: %s to hcn namespace: %s due to error: %v",
			hnsResponse.Id, namespace.Id, err)
	}

	defer func() {
		if err != nil {
			if errRemoveNsEp := hcn.RemoveNamespaceEndpoint(namespace.Id, hnsResponse.Id); errRemoveNsEp != nil {
				log.Printf("[net] Failed to remove endpoint: %s from namespace: %s due to error: %v",
					hnsResponse.Id, hnsResponse.Id, errRemoveNsEp)
			}
		}
	}()

	// If the host <-> container connectivity is requested, create endpoint in HostNCApipaNetwork
	//if epInfo.AllowInboundFromHostToNC || epInfo.AllowInboundFromNCToHost {
	if err = nw.createHostNCApipaEndpoint(epInfo); err != nil {
		return nil, fmt.Errorf("Failed to create HostNCApipaEndpoint due to error: %v", err)
		// TODO: delete the endpoint created above and return appropriate error.
	}
	//}

	var vlanid int
	if epInfo.Data != nil {
		if vlanData, ok := epInfo.Data[VlanIDKey]; ok {
			vlanid = vlanData.(int)
		}
	}

	var gateway net.IP
	if len(hnsResponse.Routes) > 0 {
		gateway = net.ParseIP(hnsResponse.Routes[0].NextHop)
	}

	log.Errorf("[net] tempdebug: HostNCApipaEndpointID: %s", epInfo.HostNCApipaEndpointID)

	// Create the endpoint object.
	ep := &endpoint{
		Id:               hcnEndpoint.Name,
		HnsId:            hnsResponse.Id,
		SandboxKey:       epInfo.ContainerID,
		IfName:           epInfo.IfName,
		IPAddresses:      epInfo.IPAddresses,
		Gateways:         []net.IP{gateway},
		DNS:              epInfo.DNS,
		VlanID:           vlanid,
		EnableSnatOnHost: epInfo.EnableSnatOnHost,
		NetNs:            epInfo.NetNsPath,
		HostNCApipaEndpointID: epInfo.HostNCApipaEndpointID,
		NetworkID:             epInfo.NetworkID,
	}

	for _, route := range epInfo.Routes {
		ep.Routes = append(ep.Routes, route)
	}

	ep.MacAddress, _ = net.ParseMAC(hnsResponse.MacAddress)

	return ep, nil
}

// deleteEndpointImpl deletes an existing endpoint from the network.
func (nw *network) deleteEndpointImpl(ep *endpoint) error {
	if useHnsV2, err := UseHnsV2(ep.NetNs); useHnsV2 {
		if err != nil {
			return err
		}

		return nw.deleteEndpointImplHnsV2(ep)
	}

	return nw.deleteEndpointImplHnsV1(ep)
}

// deleteEndpointImplHnsV1 deletes an existing endpoint from the network using HNS v1.
func (nw *network) deleteEndpointImplHnsV1(ep *endpoint) error {
	log.Printf("[net] HNSEndpointRequest DELETE id:%v", ep.HnsId)
	hnsResponse, err := hcsshim.HNSEndpointRequest("DELETE", ep.HnsId, "")
	log.Printf("[net] HNSEndpointRequest DELETE response:%+v err:%v.", hnsResponse, err)

	return err
}

// deleteEndpointImplHnsV2 deletes an existing endpoint from the network using HNS v2.
func (nw *network) deleteEndpointImplHnsV2(ep *endpoint) error {
	var (
		hcnEndpoint *hcn.HostComputeEndpoint
		err         error
	)

	log.Printf("[net] deleteEndpointImplHnsV2 DELETE id:%+v", ep)
	//if epInfo.AllowInboundFromHostToNC || epInfo.AllowInboundFromNCToHost {
	{
		if err = nw.deleteHostNCApipaEndpoint(ep.HostNCApipaEndpointID); err != nil {
			log.Errorf("[net] Failed to delete APIPA endpoint due to error: %v", err)
			return err
		}
	}

	log.Printf("[net] Deleting hcn endpoint with id: %s", ep.HnsId)

	if hcnEndpoint, err = hcn.GetEndpointByID(ep.HnsId); err != nil {
		return fmt.Errorf("Failed to get hcn endpoint with id: %s due to err: %v", ep.HnsId, err)
	}

	// Remove this endpoint from the namespace
	if err = hcn.RemoveNamespaceEndpoint(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id); err != nil {
		return fmt.Errorf("Failed to remove hcn endpoint: %s from namespace: %s due to error: %v", ep.HnsId,
			hcnEndpoint.HostComputeNamespace, err)
	}

	if err = hcnEndpoint.Delete(); err != nil {
		return fmt.Errorf("Failed to delete hcn endpoint: %s due to error: %v", ep.HnsId, err)
	}

	log.Printf("[net] Successfully deleted hcn endpoint with id: %s", ep.HnsId)

	return nil
}

// getInfoImpl returns information about the endpoint.
func (ep *endpoint) getInfoImpl(epInfo *EndpointInfo) {
	epInfo.Data["hnsid"] = ep.HnsId
}

// updateEndpointImpl in windows does nothing for now
func (nw *network) updateEndpointImpl(existingEpInfo *EndpointInfo, targetEpInfo *EndpointInfo) (*endpoint, error) {
	return nil, nil
}
