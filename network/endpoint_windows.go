// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package network

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/google/uuid"
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
	// Check if the netNsPath is a valid GUID to decide on HNSv1 or HNSv2
	if _, err := uuid.Parse(epInfo.NetNsPath); err == nil {
		if err = hcn.V2ApiSupported(); err != nil {
			log.Printf("HNSV2 is not supported on this windows platform")
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

	// Attach the endpoint.
	log.Printf("[net] Attaching endpoint %v to container %v.", hnsResponse.Id, epInfo.ContainerID)
	err = hcsshim.HotAttachEndpoint(epInfo.ContainerID, hnsResponse.Id)
	if err != nil {
		log.Printf("[net] Failed to attach endpoint: %v.", err)
		return nil, err
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

// newEndpointImplHnsV2 creates a new endpoint in the network using HnsV2
func (nw *network) newEndpointImplHnsV2(epInfo *EndpointInfo) (*endpoint, error) {
	var vlanid int
	if epInfo.Data != nil {
		if _, ok := epInfo.Data[VlanIDKey]; ok {
			vlanid = epInfo.Data[VlanIDKey].(int)
		}
	}

	infraEpName, _ := ConstructEndpointID(epInfo.ContainerID, epInfo.NetNsPath, epInfo.IfName)

	hnsEndpoint := &hcn.HostComputeEndpoint{
		Name:               infraEpName,
		HostComputeNetwork: nw.HnsId,
		//HostComputeNamespace: epInfo.NetNsPath,
		Dns: hcn.Dns{
			Domain:     epInfo.DNS.Suffix,
			ServerList: epInfo.DNS.Servers,
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		MacAddress: epInfo.MacAddress.String(),
	}

	if endpointPolicies, err := policy.GetHcnEndpointPolicies(policy.EndpointPolicy, epInfo.Policies, epInfo.Data); err == nil {
		for _, epPolicy := range endpointPolicies {
			hnsEndpoint.Policies = append(hnsEndpoint.Policies, epPolicy)
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

		hnsEndpoint.Routes = append(hnsEndpoint.Routes, hcnRoute)
	}

	for _, ipAddress := range epInfo.IPAddresses {
		prefixLength, _ := ipAddress.Mask.Size()
		ipConfiguration := hcn.IpConfig{
			IpAddress:    ipAddress.IP.String(),
			PrefixLength: uint8(prefixLength),
		}
		hnsEndpoint.IpConfigurations = append(hnsEndpoint.IpConfigurations, ipConfiguration)
	}

	// Create the HNS endpoint.
	log.Printf("[net] HostComputeEndpoint CREATE: %+v", hnsEndpoint)
	hnsResponse, err := hnsEndpoint.Create()
	log.Printf("[net] HostComputeEndpoint CREATE response: %+v err: %v", hnsResponse, err)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			log.Printf("[net] HostComputeEndpoint DELETE id: %v", hnsResponse.Id)
			err = hnsResponse.Delete()
			log.Printf("[net] HostComputeEndpoint DELETE err: %v", err)
		}
	}()

	log.Printf("[net] GetNamespaceByID id: %s", epInfo.NetNsPath)
	namespace, e := hcn.GetNamespaceByID(epInfo.NetNsPath)
	log.Printf("[net] GetNamespaceByID result: %+v", namespace)
	if e != nil {
		err = e
		log.Printf("[net] GetNamespaceByID err: %v", e)
		return nil, err
	}

	log.Printf("[net] AddNamespaceEndpoint ns id: %s, ep id: %s", namespace.Id, hnsResponse.Id)
	if e = hcn.AddNamespaceEndpoint(namespace.Id, hnsResponse.Id); e != nil {
		log.Printf("[net] AddNamespaceEndpoint err %v", e)
		err = e
		return nil, err
	}

	// Create the endpoint object.
	ep := &endpoint{
		Id:               infraEpName,
		HnsId:            hnsResponse.Id,
		SandboxKey:       epInfo.ContainerID,
		IfName:           epInfo.IfName,
		IPAddresses:      epInfo.IPAddresses,
		Gateways:         []net.IP{net.ParseIP(hnsResponse.Routes[0].NextHop)},
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

// deleteEndpointImpl deletes an existing endpoint from the network.
func (nw *network) deleteEndpointImpl(ep *endpoint) error {
	// Delete the HNS endpoint.
	// Check if the netNs is a valid GUID to decide on HNSv1 or HNSv2
	if _, err := uuid.Parse(ep.NetNs); err == nil {
		if err = hcn.V2ApiSupported(); err != nil {
			log.Printf("HNSV2 is not supported on this windows platform")
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
	var hnsEndpoint *hcn.HostComputeEndpoint
	var err error
	log.Printf("[net] HostComputeEndpoint DELETE id:%v", ep.HnsId)
	if hnsEndpoint, err = hcn.GetEndpointByID(ep.HnsId); err == nil {
		err = hnsEndpoint.Delete()
	}

	log.Printf("[net] HostComputeEndpoint DELETE err:%v.", err)

	return err
}

// getInfoImpl returns information about the endpoint.
func (ep *endpoint) getInfoImpl(epInfo *EndpointInfo) {
	epInfo.Data["hnsid"] = ep.HnsId
}

// updateEndpointImpl in windows does nothing for now
func (nw *network) updateEndpointImpl(existingEpInfo *EndpointInfo, targetEpInfo *EndpointInfo) (*endpoint, error) {
	return nil, nil
}
