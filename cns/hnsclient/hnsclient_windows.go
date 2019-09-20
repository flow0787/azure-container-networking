package hnsclient

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/log"
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
	apipaNetwork *hcn.HostComputeNetwork,
	localIPConfiguration cns.IPConfiguration) (*hcn.HostComputeEndpoint, error) {
	log.Printf("[tempdebug] configureApipaEndpoint ID: %+v", apipaNetwork)
	apipaEndpoint := &hcn.HostComputeEndpoint{
		Name:               apipaEndpointName,
		HostComputeNetwork: apipaNetwork.Id,
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

// CreateApipaEndpoint creates the endpoint in the apipa network for host container connectivity
func CreateApipaEndpoint(localIPConfiguration cns.IPConfiguration) (string, error) {
	var (
		apipaNetwork  *hcn.HostComputeNetwork
		apipaEndpoint *hcn.HostComputeEndpoint
		err           error
	)

	if apipaNetwork, err = createApipaNetwork(localIPConfiguration); err != nil {
		log.Errorf("[Azure CNS] Failed to create apipa network for host container connectivity due to error: %v", err)
		return "", err
	}

	if apipaEndpoint, err = configureApipaEndpoint(apipaNetwork, localIPConfiguration); err != nil {
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
