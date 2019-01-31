package policy

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-container-networking/log"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

// SerializePolicies serializes policies to json.
func SerializePolicies(policyType CNIPolicyType, policies []Policy, epInfoData map[string]interface{}) []json.RawMessage {
	var jsonPolicies []json.RawMessage
	for _, policy := range policies {
		if policy.Type == policyType {
			if isPolicyTypeOutBoundNAT := IsPolicyTypeOutBoundNAT(policy); isPolicyTypeOutBoundNAT {
				if serializedOutboundNatPolicy, err := SerializeOutBoundNATPolicy(policy, epInfoData); err != nil {
					log.Printf("Failed to serialize OutBoundNAT policy")
				} else {
					jsonPolicies = append(jsonPolicies, serializedOutboundNatPolicy)
				}
			} else {
				jsonPolicies = append(jsonPolicies, policy.Data)
			}
		}
	}
	return jsonPolicies
}

// GetOutBoundNatExceptionList returns exception list for outbound nat policy
func GetOutBoundNatExceptionList(policy Policy) ([]string, error) {
	type KVPair struct {
		Type          CNIPolicyType   `json:"Type"`
		ExceptionList json.RawMessage `json:"ExceptionList"`
	}

	var data KVPair
	if err := json.Unmarshal(policy.Data, &data); err != nil {
		return nil, err
	}

	if data.Type == OutBoundNatPolicy {
		var exceptionList []string
		if err := json.Unmarshal(data.ExceptionList, &exceptionList); err != nil {
			return nil, err
		}

		return exceptionList, nil
	}

	log.Printf("OutBoundNAT policy not set")
	return nil, nil
}

// IsPolicyTypeOutBoundNAT return true if the policy type is OutBoundNAT
func IsPolicyTypeOutBoundNAT(policy Policy) bool {
	if policy.Type == EndpointPolicy {
		type KVPair struct {
			Type          CNIPolicyType   `json:"Type"`
			ExceptionList json.RawMessage `json:"ExceptionList"`
		}
		var data KVPair
		if err := json.Unmarshal(policy.Data, &data); err != nil {
			return false
		}

		if data.Type == OutBoundNatPolicy {
			return true
		}
	}

	return false
}

// SerializeOutBoundNATPolicy formulates OutBoundNAT policy and returns serialized json
func SerializeOutBoundNATPolicy(policy Policy, epInfoData map[string]interface{}) (json.RawMessage, error) {
	outBoundNatPolicy := hcsshim.OutboundNatPolicy{}
	outBoundNatPolicy.Policy.Type = hcsshim.OutboundNat

	exceptionList, err := GetOutBoundNatExceptionList(policy)
	if err != nil {
		log.Printf("Failed to parse outbound NAT policy %v", err)
		return nil, err
	}

	if exceptionList != nil {
		for _, ipAddress := range exceptionList {
			outBoundNatPolicy.Exceptions = append(outBoundNatPolicy.Exceptions, ipAddress)
		}
	}

	if epInfoData["cnetAddressSpace"] != nil {
		if cnetAddressSpace := epInfoData["cnetAddressSpace"].([]string); cnetAddressSpace != nil {
			for _, ipAddress := range cnetAddressSpace {
				outBoundNatPolicy.Exceptions = append(outBoundNatPolicy.Exceptions, ipAddress)
			}
		}
	}

	if outBoundNatPolicy.Exceptions != nil {
		serializedOutboundNatPolicy, _ := json.Marshal(outBoundNatPolicy)
		return serializedOutboundNatPolicy, nil
	}

	return nil, fmt.Errorf("OutBoundNAT policy not set")
}

// GetPolicyType parses the policy and returns the policy type
func GetPolicyType(policy Policy) CNIPolicyType {
	// Check if the type is OutBoundNAT
	type KVPairOutBoundNAT struct {
		Type          CNIPolicyType   `json:"Type"`
		ExceptionList json.RawMessage `json:"ExceptionList"`
	}
	var dataOutBoundNAT KVPairOutBoundNAT
	if err := json.Unmarshal(policy.Data, &dataOutBoundNAT); err == nil {
		if dataOutBoundNAT.Type == OutBoundNatPolicy {
			return OutBoundNatPolicy
		}
	}

	// Check if the type is Route
	type KVPairRoute struct {
		Type              CNIPolicyType `json:"Type"`
		DestinationPrefix string        `json:"DestinationPrefix"`
		NeedEncap         bool          `json:"NeedEncap"`
	}
	var dataRoute KVPairRoute
	if err := json.Unmarshal(policy.Data, &dataRoute); err == nil {
		if dataRoute.Type == RoutePolicy {
			return RoutePolicy
		}
	}

	// Return empty string if the policy type is invalid
	log.Printf("Returning policyType INVALID")
	return ""
}

// SerializeHcnSubnetVlanPolicy serializes subnet policy for VLAN to json.
func SerializeHcnSubnetVlanPolicy(vlanID uint32) ([]byte, error) {
	vlanPolicySetting := &hcn.VlanPolicySetting{
		IsolationId: vlanID,
	}
	vlanPolicySettingJSON, err := json.Marshal(vlanPolicySetting)
	if err != nil {
		return nil, err
	}

	vlanSubnetPolicy := &hcn.SubnetPolicy{
		Type:     hcn.VLAN,
		Settings: vlanPolicySettingJSON,
	}
	vlanSubnetPolicyJSON, err := json.Marshal(vlanSubnetPolicy)
	if err != nil {
		return nil, err
	}

	return vlanSubnetPolicyJSON, nil
}

// GetHcnNetAdapterPolicy returns network adapter name policy.
func GetHcnNetAdapterPolicy(networkAdapterName string) (hcn.NetworkPolicy, error) {
	networkAdapterNamePolicy := hcn.NetworkPolicy{
		Type: hcn.NetAdapterName,
	}

	netAdapterNamePolicySetting := &hcn.NetAdapterNameNetworkPolicySetting{
		NetworkAdapterName: networkAdapterName,
	}
	netAdapterNamePolicySettingJSON, err := json.Marshal(netAdapterNamePolicySetting)
	if err != nil {
		return networkAdapterNamePolicy, err
	}

	networkAdapterNamePolicy.Settings = netAdapterNamePolicySettingJSON

	return networkAdapterNamePolicy, nil
}

// GetHcnOutBoundNATPolicy returns outBoundNAT policy.
func GetHcnOutBoundNATPolicy(policy Policy, epInfoData map[string]interface{}) (hcn.EndpointPolicy, error) {
	outBoundNATPolicy := hcn.EndpointPolicy{
		Type: hcn.OutBoundNAT,
	}

	outBoundNATPolicySetting := hcn.OutboundNatPolicySetting{}
	exceptionList, err := GetOutBoundNatExceptionList(policy)
	if err != nil {
		log.Printf("Failed to parse outbound NAT policy %v", err)
		return outBoundNATPolicy, err
	}

	if exceptionList != nil {
		for _, ipAddress := range exceptionList {
			outBoundNATPolicySetting.Exceptions = append(outBoundNATPolicySetting.Exceptions, ipAddress)
		}
	}

	if epInfoData["cnetAddressSpace"] != nil {
		if cnetAddressSpace := epInfoData["cnetAddressSpace"].([]string); cnetAddressSpace != nil {
			for _, ipAddress := range cnetAddressSpace {
				outBoundNATPolicySetting.Exceptions = append(outBoundNATPolicySetting.Exceptions, ipAddress)
			}
		}
	}

	if outBoundNATPolicySetting.Exceptions != nil {
		outBoundNATPolicySettingJSON, err := json.Marshal(outBoundNATPolicySetting)
		if err != nil {
			return outBoundNATPolicy, err
		}

		outBoundNATPolicy.Settings = outBoundNATPolicySettingJSON
		return outBoundNATPolicy, nil
	}

	return outBoundNATPolicy, fmt.Errorf("OutBoundNAT policy not set")
}

// GetHcnRoutePolicy returns Route policy.
func GetHcnRoutePolicy(policy Policy) (hcn.EndpointPolicy, error) {
	routePolicy := hcn.EndpointPolicy{
		Type: hcn.SDNRoute,
	}

	type KVPair struct {
		Type              CNIPolicyType   `json:"Type"`
		DestinationPrefix json.RawMessage `json:"DestinationPrefix"`
		NeedEncap         json.RawMessage `json:"NeedEncap"`
	}

	var data KVPair
	if err := json.Unmarshal(policy.Data, &data); err != nil {
		return routePolicy, err
	}

	if data.Type == RoutePolicy {
		var destinationPrefix string
		var needEncap bool
		if err := json.Unmarshal(data.DestinationPrefix, &destinationPrefix); err != nil {
			return routePolicy, err
		}

		if err := json.Unmarshal(data.NeedEncap, &needEncap); err != nil {
			return routePolicy, err
		}

		sdnRoutePolicySetting := &hcn.SDNRoutePolicySetting{
			DestinationPrefix: destinationPrefix,
			NeedEncap:         needEncap,
		}
		routePolicySettingJSON, err := json.Marshal(sdnRoutePolicySetting)
		if err != nil {
			return routePolicy, err
		}

		routePolicy.Settings = routePolicySettingJSON

		return routePolicy, nil

	}

	return routePolicy, fmt.Errorf("Invalid policy: %+v. Expecting Route policy", policy)
}

// GetHcnEndpointPolicies returns array of all endpoint policies.
func GetHcnEndpointPolicies(policyType CNIPolicyType, policies []Policy, epInfoData map[string]interface{}) ([]hcn.EndpointPolicy, error) {
	var hcnEndPointPolicies []hcn.EndpointPolicy
	for _, policy := range policies {
		if policy.Type == policyType {
			var err error
			var endpointPolicy hcn.EndpointPolicy
			if OutBoundNatPolicy == GetPolicyType(policy) {
				endpointPolicy, err = GetHcnOutBoundNATPolicy(policy, epInfoData)
			} else if RoutePolicy == GetPolicyType(policy) {
				endpointPolicy, err = GetHcnRoutePolicy(policy)
			} else {
				// return error as we should be able to parse all the policies specified
				return hcnEndPointPolicies, fmt.Errorf("Failed to set Policy: Type: %s, Data: %s", policy.Type, policy.Data)
			}

			if err != nil {
				log.Printf("Failed to parse policy: %+v with error %v", policy.Data, err)
				return hcnEndPointPolicies, err
			}

			hcnEndPointPolicies = append(hcnEndPointPolicies, endpointPolicy)
			log.Printf("Successfully set the policy: %+v", endpointPolicy)
		}
	}

	return hcnEndPointPolicies, nil
}
