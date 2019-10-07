package hnsclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/network/models"
	"github.com/Azure/azure-container-networking/network/policy"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

const (
	// Name of the external hns network
	ExtHnsNetworkName = "ext"

	// Address prefix for external hns network
	ExtHnsNetworkAddressPrefix = "192.168.255.0/30"

	// Gateway address for external hns network
	ExtHnsNetworkGwAddress = "192.168.255.1"

	// HNS network types
	hnsL2Bridge = "l2bridge"
	hnsL2Tunnel = "l2tunnel"

	// hcnSchemaVersionMajor indicates major version number for hcn schema
	hcnSchemaVersionMajor = 2

	// hcnSchemaVersionMinor indicates minor version number for hcn schema
	hcnSchemaVersionMinor = 0

	// hcnIpamTypeStatic indicates the static type of ipam
	hcnIpamTypeStatic = "Static"

	// apipaNetworkName indicates the name of the apipa network used for host container connectivity
	apipaNetworkName = "apipa-network"

	// apipaEndpointName indicates the name of the apipa endpoint used for host container connectivity
	apipaEndpointName = "apipa-endpoint"
)

// CreateHnsNetwork creates the HNS network with the provided configuration
func CreateHnsNetwork(nwConfig cns.CreateHnsNetworkRequest) error {
	log.Printf("[Azure CNS] CreateHnsNetwork")
	// Initialize HNS network.
	hnsNetwork := &hcsshim.HNSNetwork{
		Name:                 nwConfig.NetworkName,
		Type:                 nwConfig.NetworkType,
		NetworkAdapterName:   nwConfig.NetworkAdapterName,
		SourceMac:            nwConfig.SourceMac,
		DNSSuffix:            nwConfig.DNSSuffix,
		DNSServerList:        nwConfig.DNSServerList,
		DNSServerCompartment: nwConfig.DNSServerCompartment,
		ManagementIP:         nwConfig.ManagementIP,
		AutomaticDNS:         nwConfig.AutomaticDNS,
	}

	for _, policy := range nwConfig.Policies {
		hnsNetwork.Policies = append(hnsNetwork.Policies, policy)
	}

	for _, subnet := range nwConfig.Subnets {
		hnsSubnet := hcsshim.Subnet{
			AddressPrefix:  subnet.AddressPrefix,
			GatewayAddress: subnet.GatewayAddress,
		}

		hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)
	}

	for _, macPool := range nwConfig.MacPools {
		hnsMacPool := hcsshim.MacPool{
			StartMacAddress: macPool.StartMacAddress,
			EndMacAddress:   macPool.EndMacAddress,
		}
		hnsNetwork.MacPools = append(hnsNetwork.MacPools, hnsMacPool)
	}

	return createHnsNetwork(hnsNetwork)
}

// DeleteHnsNetwork deletes the HNS network with the provided name
func DeleteHnsNetwork(networkName string) error {
	log.Printf("[Azure CNS] DeleteHnsNetwork")

	return deleteHnsNetwork(networkName)
}

// CreateDefaultExtNetwork creates default HNS network named ext (if it doesn't exist already)
// to create external switch on windows platform.
// This allows orchestrators to start CNS which pre-provisions the network so that the
// VM network blip / disconnect is avoided when calling cni add for the very first time.
func CreateDefaultExtNetwork(networkType string) error {
	networkType = strings.ToLower(strings.TrimSpace(networkType))
	if len(networkType) == 0 {
		return nil
	}

	if networkType != hnsL2Bridge && networkType != hnsL2Tunnel {
		return fmt.Errorf("Invalid hns network type %s", networkType)
	}

	log.Printf("[Azure CNS] CreateDefaultExtNetwork")
	extHnsNetwork, _ := hcsshim.GetHNSNetworkByName(ExtHnsNetworkName)

	if extHnsNetwork != nil {
		log.Printf("[Azure CNS] Found existing DefaultExtNetwork with type: %s", extHnsNetwork.Type)
		if !strings.EqualFold(networkType, extHnsNetwork.Type) {
			return fmt.Errorf("Network type mismatch with existing network: %s", extHnsNetwork.Type)
		}

		return nil
	}

	// create new hns network
	log.Printf("[Azure CNS] Creating DefaultExtNetwork with type %s", networkType)

	hnsNetwork := &hcsshim.HNSNetwork{
		Name: ExtHnsNetworkName,
		Type: networkType,
	}

	hnsSubnet := hcsshim.Subnet{
		AddressPrefix:  ExtHnsNetworkAddressPrefix,
		GatewayAddress: ExtHnsNetworkGwAddress,
	}

	hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)

	return createHnsNetwork(hnsNetwork)
}

// DeleteDefaultExtNetwork deletes the default HNS network
func DeleteDefaultExtNetwork() error {
	log.Printf("[Azure CNS] DeleteDefaultExtNetwork")

	return deleteHnsNetwork(ExtHnsNetworkName)
}

// createHnsNetwork calls the hcshim to create the hns network
func createHnsNetwork(hnsNetwork *hcsshim.HNSNetwork) error {
	// Marshal the request.
	buffer, err := json.Marshal(hnsNetwork)
	if err != nil {
		return err
	}
	hnsRequest := string(buffer)

	// Create the HNS network.
	log.Printf("[Azure CNS] HNSNetworkRequest POST request:%+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
	log.Printf("[Azure CNS] HNSNetworkRequest POST response:%+v err:%v.", hnsResponse, err)

	return err
}

// deleteHnsNetwork calls HNS to delete the network with the provided name
func deleteHnsNetwork(networkName string) error {
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err == nil {
		// Delete the HNS network.
		var hnsResponse *hcsshim.HNSNetwork
		log.Printf("[Azure CNS] HNSNetworkRequest DELETE id:%v", hnsNetwork.Id)
		hnsResponse, err = hcsshim.HNSNetworkRequest("DELETE", hnsNetwork.Id, "")
		log.Printf("[Azure CNS] HNSNetworkRequest DELETE response:%+v err:%v.", hnsResponse, err)
	}

	return err
}

func configureApipaNetwork(localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeNetwork, error) {
	apipaNetwork := &hcn.HostComputeNetwork{
		Name: apipaNetworkName,
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
		Type: hcn.L2Bridge,
	}

	// TODO: How to get this string from the created loopback adapter?
	// TODO: Create the loopback adapter using the LocalIPConfiguration passed in.
	if netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy("Ethernet 6"); err == nil {
		apipaNetwork.Policies = append(apipaNetwork.Policies, netAdapterNamePolicy)
	} else {
		log.Errorf("[Azure CNS] Failed to serialize network adapter policy due to error: %v", err)
		return nil, err
	}

	// Calculate subnet prefix
	var subnetPrefix net.IPNet
	var subnetPrefixStr string
	ipAddr := net.ParseIP(localIPConfiguration.IPSubnet.IPAddress)
	if ipAddr.To4() != nil {
		subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 32)}
	} else if ipAddr.To16() != nil {
		subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 128)}
	} else {
		return nil, fmt.Errorf("[Azure CNS] Failed get subnet prefix for localIPConfiguration: %+v", localIPConfiguration)
	}

	subnetPrefix.IP = ipAddr.Mask(subnetPrefix.Mask)
	subnetPrefixStr = subnetPrefix.IP.String() + "/" + strconv.Itoa(int(localIPConfiguration.IPSubnet.PrefixLength))
	log.Printf("[tempdebug] configureApipaNetwork: subnetPrefixStr: %s, GW: %s", subnetPrefixStr, localIPConfiguration.GatewayIPAddress)

	subnet := hcn.Subnet{
		//IpAddressPrefix: "169.254.0.0/16", // TODO: this needs be calculated from LocalIPConfiguration passed in
		IpAddressPrefix: subnetPrefixStr,
		Routes: []hcn.Route{
			hcn.Route{
				NextHop:           localIPConfiguration.GatewayIPAddress,
				DestinationPrefix: "0.0.0.0/0",
			},
		},
	}

	apipaNetwork.Ipams[0].Subnets = append(apipaNetwork.Ipams[0].Subnets, subnet)

	return apipaNetwork, nil
}

func createApipaNetwork(localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeNetwork, error) {
	var (
		apipaNetwork *hcn.HostComputeNetwork
		err          error
	)

	// Check if the APIPA network exists
	if apipaNetwork, err = hcn.GetNetworkByName(apipaNetworkName); err != nil {
		// If error is anything other than networkNotFound, mark this as error
		// TODO: why is following part not working?
		/*
			if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
				return nil, fmt.Errorf("[Azure CNS] ERROR: createApipaNetwork failed due to error with GetNetworkByName: %v", err)
			}
		*/

		// APIPA network doesn't exist. Create one.
		if apipaNetwork, err = configureApipaNetwork(localIPConfiguration); err != nil {
			log.Printf("[Azure CNS] Failed to configure apipa network due to error: %v", err)
			return nil, err
		}

		// Create the HNS network.
		log.Printf("[net] Creating apipa network: %+v", apipaNetwork)
		apipaNetwork, err = apipaNetwork.Create()

		if err != nil {
			log.Printf("[net] Failed to create apipa network due to error: %v", err)
			return nil, fmt.Errorf("Failed to create apipa network: %s due to error: %v", apipaNetwork.Name, err)
		}

		log.Printf("[net] Successfully created apipa network for host container connectivity: %+v", apipaNetwork)
	} else {
		log.Printf("[Azure CNS] Found existing APIPA network: %+v", apipaNetwork)
	}

	return apipaNetwork, err
}

func configureApipaEndpoint(
	apipaNetworkID string,
	localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeEndpoint, error) {
	//log.Printf("[tempdebug] configureApipaEndpoint ID: %+v", apipaNetwork)
	apipaEndpoint := &hcn.HostComputeEndpoint{
		Name:               apipaEndpointName,
		HostComputeNetwork: apipaNetworkID,
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
	}

	localIP := localIPConfiguration.IPSubnet.IPAddress
	remoteIP := localIPConfiguration.GatewayIPAddress
	log.Printf("[tempdebug] configureApipaEndpoint localIP: %s, remoteIP: %s", localIP, remoteIP)
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "1",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "1",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "6",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "6",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing out to host apipa
		aclOutAllowToHostOnly := hcn.AclPolicySetting{
			Protocols:       "17",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeOut,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)

		// Add endpoint ACL for allowing in from host apipa
		aclInAllowFromHostOnly := hcn.AclPolicySetting{
			Protocols:       "17",
			Action:          hcn.ActionTypeAllow,
			Direction:       hcn.DirectionTypeIn,
			LocalAddresses:  localIP,
			RemoteAddresses: remoteIP,
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

		apipaEndpoint.Policies = append(apipaEndpoint.Policies, endpointPolicy)
	}
	/********************************************************************************************************/

	nexthop := remoteIP
	hcnRoute := hcn.Route{
		NextHop:           nexthop,
		DestinationPrefix: "0.0.0.0/0",
	}

	apipaEndpoint.Routes = append(apipaEndpoint.Routes, hcnRoute)

	ipConfiguration := hcn.IpConfig{
		IpAddress:    localIP,
		PrefixLength: localIPConfiguration.IPSubnet.PrefixLength, // TODO: this should come from the cns config
	}

	apipaEndpoint.IpConfigurations = append(apipaEndpoint.IpConfigurations, ipConfiguration)

	return apipaEndpoint, nil
}

//TODO: lock
// CreateApipaEndpoint creates the endpoint in the apipa network for host container connectivity
func CreateApipaEndpoint(localIPConfiguration cns.IPConfiguration) (string, error) {
	var (
		apipaNetwork  *hcn.HostComputeNetwork
		apipaEndpoint *hcn.HostComputeEndpoint
		err           error
	)

	//TODO: check if the endpoint exists
	if apipaNetwork, err = createApipaNetwork(localIPConfiguration); err != nil {
		log.Errorf("[Azure CNS] Failed to create apipa network for host container connectivity due to error: %v", err)
		return "", err
	}

	if apipaEndpoint, err = configureApipaEndpoint(apipaNetwork.Id, localIPConfiguration); err != nil {
		log.Errorf("[Azure CNS] Failed to configure apipa endpoint for host container connectivity due to error: %v", err)
		return "", err
	}

	// Create the apipa endpoint
	log.Printf("[Azure CNS] Creating apipa endpoint for host-container connectivity: %+v", apipaEndpoint)
	if apipaEndpoint, err = apipaEndpoint.Create(); err != nil {
		err = fmt.Errorf("Failed to create apipa endpoint: %s due to error: %v", apipaEndpoint.Name, err)
		log.Errorf("[Azure CNS] %s", err.Error())
		return "", err
	}

	log.Printf("[Azure CNS] Successfully created apipa endpoint for host-container connectivity: %+v", apipaEndpoint)

	return apipaEndpoint.Id, nil
}

//TODO: lock
// DeleteApipaEndpoint deletes the endpoint in the apipa network created for host <-> container connectivity
// Can this be generalized to createEndpoint / DeleteEndpoint - which can used by general CNI calls
// If you don't delete this APIPA network / if VM gets rebooted, how will you clean this upon restart?
func DeleteApipaEndpoint(endpointID string) error {
	var (
		apipaEndpoint *hcn.HostComputeEndpoint
		err           error
	)

	// Check if the endpoint with the provided ID exists
	if apipaEndpoint, err = hcn.GetEndpointByID(endpointID); err != nil {
		// If error is anything other than EndpointNotFoundError, return error.
		// else log the error but don't return error because endpoint is already deleted.
		if _, endpointNotFound := err.(hcn.EndpointNotFoundError); !endpointNotFound {
			return fmt.Errorf("[Azure CNS] ERROR: DeleteApipaEndpoint failed due to "+
				"error with GetEndpointByName: %v", err)
		}

		log.Errorf("[Azure CNS] Failed to find endpoint: %s for deletion due to error: %v", endpointID, err)
		return nil
	}

	//networkID := apipaEndpoint.HostComputeNetwork

	if err = apipaEndpoint.Delete(); err != nil {
		err = fmt.Errorf("Failed to delete endpoint: %+v due to error: %v", apipaEndpoint, err)
		log.Errorf("[Azure CNS] %v", err)
		return err
	}

	log.Debugf("[Azure CNS] Successfully deleted endpoint: %v", apipaNetworkName)

	var endpoints []hcn.HostComputeEndpoint
	// Check if the network has any endpoints left
	if endpoints, err = hcn.ListEndpointsOfNetwork(apipaEndpoint.HostComputeNetwork); err != nil {
		log.Errorf("[Azure CNS] Failed to list endpoints in the network: %s due to error: %v", apipaNetworkName, err)
		return nil
	}

	// Delete network if it doesn't have any endpoints
	if len(endpoints) == 0 {
		if err = DeleteApipaNetwork(apipaEndpoint.HostComputeNetwork); err == nil {
			// Delete the loopback adapter created for this network
			deleteLoopbackAdapter("LoopbackAdapterHostNCConnectivity")
		}
	}

	return nil
}

func DeleteApipaNetwork(networkID string) error {
	var (
		network *hcn.HostComputeNetwork
		err     error
	)

	if network, err = hcn.GetNetworkByID(networkID); err != nil {
		// If error is anything other than NetworkNotFoundError, return error.
		// else log the error but don't return error because network is already deleted.
		if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
			return fmt.Errorf("[Azure CNS] ERROR: DeleteApipaNetwork failed due to "+
				"error with GetNetworkByID: %v", err)
		}

		log.Errorf("[Azure CNS] Failed to find network with ID: %s for deletion", networkID)
		return nil
	}

	if err = network.Delete(); err != nil {
		err = fmt.Errorf("Failed to delete network: %+v due to error: %v", network, err)
		log.Errorf("[Azure CNS] %v", err)
		return err
	}

	log.Errorf("[Azure CNS] Successfully deleted network: %+v", network)

	return nil
}

func CreateNewNetwork(
	networkInfo models.NetworkInfo,
	extInterface models.ExternalInterface) /**hcn.HostComputeNetwork, replace this by network.network*/ error {
	var (
		apipaNetwork *hcn.HostComputeNetwork
		err          error
	)

	// Check if the APIPA network exists
	if apipaNetwork, err = hcn.GetNetworkByName(networkInfo.Id); err != nil {
		// If error is anything other than networkNotFound, mark this as error
		// TODO: why is following part not working?
		/*
			if _, networkNotFound := err.(hcn.NetworkNotFoundError); !networkNotFound {
				return nil, fmt.Errorf("[Azure CNS] ERROR: createApipaNetwork failed due to error with GetNetworkByName: %v", err)
			}
		*/

		// APIPA network doesn't exist. Create one.
		if apipaNetwork, err = configureApipaNetwork2(networkInfo, extInterface); err != nil {
			log.Printf("[Azure CNS] Failed to configure apipa network due to error: %v", err)
			return err
		}

		// Create the HNS network.
		log.Printf("[net] Creating apipa network: %+v", apipaNetwork)
		apipaNetwork, err = apipaNetwork.Create()

		if err != nil {
			log.Printf("[net] Failed to create apipa network due to error: %v", err)
			return fmt.Errorf("Failed to create apipa network: %s due to error: %v", apipaNetwork.Name, err)
		}

		log.Printf("[net] Successfully created apipa network for host container connectivity: %+v", apipaNetwork)
	} else {
		log.Printf("[Azure CNS] Found existing APIPA network: %+v", apipaNetwork)
	}

	return nil
}

func configureApipaNetwork2(
	networkInfo models.NetworkInfo,
	extInterface models.ExternalInterface) (*hcn.HostComputeNetwork, error) {
	// TODO: this needs to be the generic hnsv2 path implementation
	apipaNetwork := &hcn.HostComputeNetwork{
		Name: networkInfo.Id,
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type: hcnIpamTypeStatic,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaVersionMajor,
			Minor: hcnSchemaVersionMinor,
		},
		Type: hcn.L2Bridge,
	}

	// Create loopback adapter if needed
	// TODO: check the settings from the options in networkInfo and create the loopback adapter if needed.
	ipconfig := cns.IPConfiguration{
		IPSubnet: cns.IPSubnet{
			IPAddress:    "169.254.0.2",
			PrefixLength: 16,
		},
		GatewayIPAddress: "169.254.0.2",
	}

	if exists, _ := interfaceExists("LoopbackAdapterHostNCConnectivity"); !exists {
		if err := createLoopbackAdapter("LoopbackAdapterHostNCConnectivity", ipconfig); err != nil {
			err = fmt.Errorf("Failed to create loopback adapter for host container connectivity due to error: %v", err)
			log.Errorf("[Azure CNS] %v", err)
			return nil, err
		}
	}

	if netAdapterNamePolicy, err := policy.GetHcnNetAdapterPolicy( /*"Ethernet 6"*/ "LoopbackAdapterHostNCConnectivity"); err == nil {
		apipaNetwork.Policies = append(apipaNetwork.Policies, netAdapterNamePolicy)
	} else {
		log.Errorf("[Azure CNS] Failed to serialize network adapter policy due to error: %v", err)
		return nil, err
	}

	/*
		// Calculate subnet prefix
		var subnetPrefix net.IPNet
		var subnetPrefixStr string
		ipAddr := net.ParseIP(localIPConfiguration.IPSubnet.IPAddress)
		if ipAddr.To4() != nil {
			subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 32)}
		} else if ipAddr.To16() != nil {
			subnetPrefix = net.IPNet{Mask: net.CIDRMask(int(localIPConfiguration.IPSubnet.PrefixLength), 128)}
		} else {
			return nil, fmt.Errorf("[Azure CNS] Failed get subnet prefix for localIPConfiguration: %+v", localIPConfiguration)
		}

		subnetPrefix.IP = ipAddr.Mask(subnetPrefix.Mask)
		subnetPrefixStr = subnetPrefix.IP.String() + "/" + strconv.Itoa(int(localIPConfiguration.IPSubnet.PrefixLength))
		log.Printf("[tempdebug] configureApipaNetwork: subnetPrefixStr: %s, GW: %s", subnetPrefixStr, localIPConfiguration.GatewayIPAddress)
	*/
	subnet := hcn.Subnet{
		IpAddressPrefix: "169.254.0.0/16", // TODO: this needs be calculated from LocalIPConfiguration passed in
		//IpAddressPrefix: subnetPrefixStr,
		Routes: []hcn.Route{
			hcn.Route{
				//NextHop:           localIPConfiguration.GatewayIPAddress,
				NextHop:           "169.254.0.2",
				DestinationPrefix: "0.0.0.0/0",
			},
		},
	}

	apipaNetwork.Ipams[0].Subnets = append(apipaNetwork.Ipams[0].Subnets, subnet)

	return apipaNetwork, nil
}

func CreateNewEndpoint(
	endpointInfo models.EndpointInfo,
	localIPConfiguration cns.IPConfiguration) (string, error) {
	var (
		//apipaNetwork  *hcn.HostComputeNetwork
		apipaEndpoint *hcn.HostComputeEndpoint
		err           error
	)

	//TODO: this needs to be generic implementation of create endpoint with v2

	//TODO: check if the endpoint exists

	/*
		if apipaNetwork, err = createApipaNetwork(localIPConfiguration); err != nil {
			log.Errorf("[Azure CNS] Failed to create apipa network for host container connectivity due to error: %v", err)
			return "", err
		}
	*/

	if apipaEndpoint, err = configureApipaEndpoint(endpointInfo.NetworkID, localIPConfiguration); err != nil {
		log.Errorf("[Azure CNS] Failed to configure apipa endpoint for host container connectivity due to error: %v", err)
		return "", err
	}

	// Create the apipa endpoint
	log.Printf("[Azure CNS] Creating apipa endpoint for host-container connectivity: %+v", apipaEndpoint)
	if apipaEndpoint, err = apipaEndpoint.Create(); err != nil {
		err = fmt.Errorf("Failed to create apipa endpoint: %s due to error: %v", apipaEndpoint.Name, err)
		log.Errorf("[Azure CNS] %s", err.Error())
		return "", err
	}

	log.Printf("[Azure CNS] Successfully created apipa endpoint for host-container connectivity: %+v", apipaEndpoint)

	return apipaEndpoint.Id, nil
}

func interfaceExists(iFaceName string) (bool, error) {
	_, err := net.InterfaceByName(iFaceName)
	if err != nil {
		errMsg := fmt.Sprintf("[Azure CNS] Unable to get interface by name %s. Error: %v", iFaceName, err)
		log.Printf(errMsg)
		return false, fmt.Errorf(errMsg)
	}

	log.Printf("[Azure CNS] Found interface by name %s", iFaceName)

	return true, nil
}

func createLoopbackAdapter(
	adapterName string,
	ipConfig cns.IPConfiguration) error {
	if _, err := os.Stat("./AzureNetworkContainer.exe"); err != nil {
		return fmt.Errorf("[Azure CNS] Unable to find AzureNetworkContainer.exe. Cannot continue")
	}

	if ipConfig.IPSubnet.IPAddress == "" {
		return fmt.Errorf("[Azure CNS] IPAddress in IPConfiguration is nil")
	}

	ipv4AddrCidr := fmt.Sprintf("%v/%d", ipConfig.IPSubnet.IPAddress, ipConfig.IPSubnet.PrefixLength)
	log.Printf("[Azure CNS] Created ipv4Cidr as %v", ipv4AddrCidr)
	ipv4Addr, _, err := net.ParseCIDR(ipv4AddrCidr)
	ipv4NetInt := net.CIDRMask((int)(ipConfig.IPSubnet.PrefixLength), 32)
	log.Printf("[Azure CNS] Created netmask as %v", ipv4NetInt)
	ipv4NetStr := fmt.Sprintf("%d.%d.%d.%d", ipv4NetInt[0], ipv4NetInt[1], ipv4NetInt[2], ipv4NetInt[3])
	log.Printf("[Azure CNS] Created netmask in string format %v", ipv4NetStr)

	args := []string{"/C", "AzureNetworkContainer.exe", "/logpath", log.GetLogDirectory(),
		"/name",
		adapterName,
		"/operation",
		"CREATE",
		"/ip",
		ipv4Addr.String(),
		"/netmask",
		ipv4NetStr,
		"/gateway",
		ipConfig.GatewayIPAddress,
		"/weakhostsend",
		"true",
		"/weakhostreceive",
		"true"}

	c := exec.Command("cmd", args...)

	//loopbackOperationLock.Lock()
	log.Printf("[Azure CNS] Going to create/update network loopback adapter: %v", args)
	bytes, err := c.Output()
	/*
		if err == nil {
			err = setWeakHostOnInterface(createNetworkContainerRequest.PrimaryInterfaceIdentifier,
				createNetworkContainerRequest.NetworkContainerid)
		}
	*/
	//loopbackOperationLock.Unlock()

	if err == nil {
		log.Printf("[Azure CNS] Successfully created network loopback adapter for ipConfig: %+v. Output:%v.",
			ipConfig, string(bytes))
	} else {
		log.Printf("Failed to create loopback adapter for IP config: %+v. Error: %v. Output: %v",
			ipConfig, err, string(bytes))
	}

	return err
}

func deleteLoopbackAdapter(adapterName string) error {
	if _, err := os.Stat("./AzureNetworkContainer.exe"); err != nil {
		return fmt.Errorf("[Azure CNS] Unable to find AzureNetworkContainer.exe. Cannot continue")
	}

	if adapterName == "" {
		return errors.New("[Azure CNS] Adapter name is not specified")
	}

	args := []string{"/C", "AzureNetworkContainer.exe", "/logpath", log.GetLogDirectory(),
		"/name",
		adapterName,
		"/operation",
		"DELETE"}

	c := exec.Command("cmd", args...)

	//loopbackOperationLock.Lock()
	log.Printf("[Azure CNS] Going to delete network loopback adapter: %v", args)
	bytes, err := c.Output()
	//	loopbackOperationLock.Unlock()

	if err == nil {
		log.Printf("[Azure CNS] Successfully deleted loopback adapter: %s. Output: %v.",
			adapterName, string(bytes))
	} else {
		log.Printf("Failed to delete loopback adapter: %s. Error: %v. Output: %v",
			adapterName, err, string(bytes))
		//return err
	}
	return err
}
