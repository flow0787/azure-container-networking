// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package restserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-container-networking/cns"
	"github.com/Azure/azure-container-networking/cns/common"
	"github.com/Azure/azure-container-networking/cns/dockerclient"
	"github.com/Azure/azure-container-networking/cns/imdsclient"
	"github.com/Azure/azure-container-networking/cns/ipamclient"
	"github.com/Azure/azure-container-networking/cns/networkcontainers"
	"github.com/Azure/azure-container-networking/cns/routes"
	acn "github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/log"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Azure/azure-container-networking/store"
	"github.com/Microsoft/hcsshim"
)

const (
	// Key against which CNS state is persisted.
	storeKey        = "ContainerNetworkService"
	swiftAPIVersion = "1"
)

// HTTPRestService represents http listener for CNS - Container Networking Service.
type HTTPRestService struct {
	*cns.Service
	dockerClient     *dockerclient.DockerClient
	imdsClient       *imdsclient.ImdsClient
	ipamClient       *ipamclient.IpamClient
	networkContainer *networkcontainers.NetworkContainers
	routingTable     *routes.RoutingTable
	store            store.KeyValueStore
	state            *httpRestServiceState
	lock             sync.Mutex
	dncPartitionKey  string
}

// containerstatus is used to save status of an existing container
type containerstatus struct {
	ID                            string
	VMVersion                     string
	HostVersion                   string
	CreateNetworkContainerRequest cns.CreateNetworkContainerRequest
}

// httpRestServiceState contains the state we would like to persist.
type httpRestServiceState struct {
	Location                         string
	NetworkType                      string
	OrchestratorType                 string
	Initialized                      bool
	ContainerIDByOrchestratorContext map[string]string          // OrchestratorContext is key and value is NetworkContainerID.
	ContainerStatus                  map[string]containerstatus // NetworkContainerID is key.
	Networks                         map[string]*networkInfo
	CompartmentInfo                  map[int][]string
	TimeStamp                        time.Time
}

type networkInfo struct {
	NetworkName string
	NicInfo     *imdsclient.InterfaceInfo
	Options     map[string]interface{}
}

// HTTPService describes the min API interface that every service should have.
type HTTPService interface {
	common.ServiceAPI
}

// NewHTTPRestService creates a new HTTP Service object.
func NewHTTPRestService(config *common.ServiceConfig) (HTTPService, error) {
	service, err := cns.NewService(config.Name, config.Version, config.Store)
	if err != nil {
		return nil, err
	}

	imdsClient := &imdsclient.ImdsClient{}
	routingTable := &routes.RoutingTable{}
	nc := &networkcontainers.NetworkContainers{}
	dc, err := dockerclient.NewDefaultDockerClient(imdsClient)

	if err != nil {
		return nil, err
	}

	ic, err := ipamclient.NewIpamClient("")
	if err != nil {
		return nil, err
	}

	serviceState := &httpRestServiceState{}
	serviceState.Networks = make(map[string]*networkInfo)
	serviceState.CompartmentInfo = make(map[int][]string)

	return &HTTPRestService{
		Service:          service,
		store:            service.Service.Store,
		dockerClient:     dc,
		imdsClient:       imdsClient,
		ipamClient:       ic,
		networkContainer: nc,
		routingTable:     routingTable,
		state:            serviceState,
	}, nil

}

// Start starts the CNS listener.
func (service *HTTPRestService) Start(config *common.ServiceConfig) error {

	err := service.Initialize(config)
	if err != nil {
		log.Errorf("[Azure CNS]  Failed to initialize base service, err:%v.", err)
		return err
	}

	err = service.restoreState()
	if err != nil {
		log.Errorf("[Azure CNS]  Failed to restore service state, err:%v.", err)
		return err
	}

	err = service.restoreNetworkState()
	if err != nil {
		log.Errorf("[Azure CNS]  Failed to restore network state, err:%v.", err)
		return err
	}

	// Add handlers.
	listener := service.Listener
	// default handlers
	listener.AddHandler(cns.SetEnvironmentPath, service.setEnvironment)
	listener.AddHandler(cns.CreateNetworkPath, service.createNetwork)
	listener.AddHandler(cns.DeleteNetworkPath, service.deleteNetwork)
	listener.AddHandler(cns.ReserveIPAddressPath, service.reserveIPAddress)
	listener.AddHandler(cns.ReleaseIPAddressPath, service.releaseIPAddress)
	listener.AddHandler(cns.GetHostLocalIPPath, service.getHostLocalIP)
	listener.AddHandler(cns.GetIPAddressUtilizationPath, service.getIPAddressUtilization)
	listener.AddHandler(cns.GetUnhealthyIPAddressesPath, service.getUnhealthyIPAddresses)
	listener.AddHandler(cns.CreateOrUpdateNetworkContainer, service.createOrUpdateNetworkContainer)
	listener.AddHandler(cns.DeleteNetworkContainer, service.deleteNetworkContainer)
	listener.AddHandler(cns.GetNetworkContainerStatus, service.getNetworkContainerStatus)
	listener.AddHandler(cns.GetInterfaceForContainer, service.getInterfaceForContainer)
	listener.AddHandler(cns.SetOrchestratorType, service.setOrchestratorType)
	listener.AddHandler(cns.GetNetworkContainerByOrchestratorContext, service.getNetworkContainerByOrchestratorContext)
	listener.AddHandler(cns.AttachContainerToNetwork, service.attachNetworkContainerToNetwork)
	listener.AddHandler(cns.DetachContainerFromNetwork, service.detachNetworkContainerFromNetwork)
	listener.AddHandler(cns.CreateCompartmentWithNCs, service.createCompartmentWithNCs)
	listener.AddHandler(cns.DeleteCompartmentWithNCs, service.deleteCompartmentWithNCs)
	listener.AddHandler(cns.AttachNcToCompartment, service.attachNcToCompartment)
	listener.AddHandler(cns.DetachNcfromCompartment, service.detachNcFromCompartment)

	// handlers for v0.2
	listener.AddHandler(cns.V2Prefix+cns.SetEnvironmentPath, service.setEnvironment)
	listener.AddHandler(cns.V2Prefix+cns.CreateNetworkPath, service.createNetwork)
	listener.AddHandler(cns.V2Prefix+cns.DeleteNetworkPath, service.deleteNetwork)
	listener.AddHandler(cns.V2Prefix+cns.ReserveIPAddressPath, service.reserveIPAddress)
	listener.AddHandler(cns.V2Prefix+cns.ReleaseIPAddressPath, service.releaseIPAddress)
	listener.AddHandler(cns.V2Prefix+cns.GetHostLocalIPPath, service.getHostLocalIP)
	listener.AddHandler(cns.V2Prefix+cns.GetIPAddressUtilizationPath, service.getIPAddressUtilization)
	listener.AddHandler(cns.V2Prefix+cns.GetUnhealthyIPAddressesPath, service.getUnhealthyIPAddresses)
	listener.AddHandler(cns.V2Prefix+cns.CreateOrUpdateNetworkContainer, service.createOrUpdateNetworkContainer)
	listener.AddHandler(cns.V2Prefix+cns.DeleteNetworkContainer, service.deleteNetworkContainer)
	listener.AddHandler(cns.V2Prefix+cns.GetNetworkContainerStatus, service.getNetworkContainerStatus)
	listener.AddHandler(cns.V2Prefix+cns.GetInterfaceForContainer, service.getInterfaceForContainer)
	listener.AddHandler(cns.V2Prefix+cns.SetOrchestratorType, service.setOrchestratorType)
	listener.AddHandler(cns.V2Prefix+cns.GetNetworkContainerByOrchestratorContext, service.getNetworkContainerByOrchestratorContext)
	listener.AddHandler(cns.V2Prefix+cns.AttachContainerToNetwork, service.attachNetworkContainerToNetwork)
	listener.AddHandler(cns.V2Prefix+cns.DetachContainerFromNetwork, service.detachNetworkContainerFromNetwork)
	listener.AddHandler(cns.V2Prefix+cns.CreateCompartmentWithNCs, service.createCompartmentWithNCs)
	listener.AddHandler(cns.V2Prefix+cns.DeleteCompartmentWithNCs, service.deleteCompartmentWithNCs)
	listener.AddHandler(cns.V2Prefix+cns.AttachNcToCompartment, service.attachNcToCompartment)
	listener.AddHandler(cns.V2Prefix+cns.DetachNcfromCompartment, service.detachNcFromCompartment)

	log.Printf("[Azure CNS]  Listening.")

	return nil
}

// Get the network info from the service network state
func (service *HTTPRestService) getCompartmentInfo(compartmentID int) ([]string, bool) {
	service.lock.Lock()
	defer service.lock.Unlock()
	compartmentInfo, found := service.state.CompartmentInfo[compartmentID]

	return compartmentInfo, found
}

// Set the network info in the service network state
func (service *HTTPRestService) addCompartmentEndpoint(compartmentID int, endpointName string) {
	service.lock.Lock()
	defer service.lock.Unlock()
	service.state.CompartmentInfo[compartmentID] = append(service.state.CompartmentInfo[compartmentID], endpointName)

	return
}

// Remove the network info from the service network state
func (service *HTTPRestService) removeCompartmentInfo(compartmentID int) {
	service.lock.Lock()
	defer service.lock.Unlock()

	if _, found := service.getCompartmentInfo(compartmentID); found {
		delete(service.state.CompartmentInfo, compartmentID)
	}

	return
}

// setupNetworkAndEndpoints.
func (service *HTTPRestService) setupNetworkAndEndpoints(ncID string, compartmentID int) error {
	log.Printf("[Azure CNS] Retrieve container state")
	containerID := "Swift_" + ncID
	containerStatus := service.state.ContainerStatus
	containerDetails, ok := containerStatus[containerID]
	if !ok {
		return fmt.Errorf("Network container: %s not found", ncID)
	}

	savedReq := containerDetails.CreateNetworkContainerRequest
	networkContainerInfo := cns.GetNetworkContainerResponse{
		IPConfiguration:            savedReq.IPConfiguration,
		Routes:                     savedReq.Routes,
		CnetAddressSpace:           savedReq.CnetAddressSpace,
		MultiTenancyInfo:           savedReq.MultiTenancyInfo,
		PrimaryInterfaceIdentifier: savedReq.PrimaryInterfaceIdentifier,
		LocalIPConfiguration:       savedReq.LocalIPConfiguration,
	}
	log.Printf("[Azure CNS] Retrieved network container state: %s %+v", containerID, networkContainerInfo)

	// validate the multitenancy info
	if networkContainerInfo.MultiTenancyInfo.EncapType != "Vlan" {
		return fmt.Errorf("Invalid multitenancy Encap type: %s. Expecting Vlan", networkContainerInfo.MultiTenancyInfo.EncapType)
	}

	if networkContainerInfo.MultiTenancyInfo.ID == 0 {
		return fmt.Errorf("Invalid multitenancy vlan id: %s", networkContainerInfo.MultiTenancyInfo.ID)
	}

	ipAddr := net.ParseIP(networkContainerInfo.IPConfiguration.IPSubnet.IPAddress)
	var subnetPrefix net.IPNet
	if ipAddr.To4() != nil {
		subnetPrefix = net.IPNet{
			IP:   ipAddr,
			Mask: net.CIDRMask(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength), 32)}
	} else {
		subnetPrefix = net.IPNet{
			IP:   ipAddr,
			Mask: net.CIDRMask(int(networkContainerInfo.IPConfiguration.IPSubnet.PrefixLength), 128)}
	}

	subnetPrefix.IP = subnetPrefix.IP.Mask(subnetPrefix.Mask)

	var hnsIDCustVNet string
	createNetwork := true
	networkName := fmt.Sprintf("azure-vlanid%v", networkContainerInfo.MultiTenancyInfo.ID)
	networkEpName := fmt.Sprintf("%s-%s", networkName, ncID)
	// Check if the network exists already
	log.Printf("[Azure CNS] Checking if the network %s is already created", networkName)
	if hnsResponse, err := hcsshim.GetHNSNetworkByName(networkName); err == nil {
		hnsIDCustVNet = hnsResponse.Id
		log.Printf("[Azure CNS] Found network %s. hnsResponse: %+v", networkName, hnsResponse)
		createNetwork = false
	}

	if createNetwork {
		// Create the HNS network.
		log.Printf("[Azure CNS] Creating network %s", networkName)
		dnsList := "10.0.0.10,168.63.129.16" // TODO: Add DNS from cns config too.
		hnsNetwork := &hcsshim.HNSNetwork{
			Name:          networkName,
			DNSServerList: dnsList,
		}
		hnsNetwork.Type = "l2bridge"
		vlanPolicy := hcsshim.VlanPolicy{
			Type: "VLAN",
		}

		vlanPolicy.VLAN = uint(networkContainerInfo.MultiTenancyInfo.ID)
		serializedVlanPolicy, _ := json.Marshal(vlanPolicy)
		hnsNetwork.Policies = append(hnsNetwork.Policies, serializedVlanPolicy)

		// Populate subnets.
		//for _, subnet := range nwInfo.Subnets {
		hnsSubnet := hcsshim.Subnet{
			AddressPrefix:  subnetPrefix.String(),
			GatewayAddress: networkContainerInfo.IPConfiguration.GatewayIPAddress,
		}

		hnsNetwork.Subnets = append(hnsNetwork.Subnets, hnsSubnet)
		//}

		// Marshal the request.
		buffer, err := json.Marshal(hnsNetwork)
		if err != nil {
			return fmt.Errorf("[Azure CNS] Failed to marshal hnsNetwork %s due to err:%v", networkName, err)
		}
		hnsRequest := string(buffer)

		// Create the HNS network.
		log.Printf("[Azure CNS] HNSNetworkRequest POST request:%+v", hnsRequest)
		hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
		log.Printf("[Azure CNS] HNSNetworkRequest POST response:%+v err:%v.", hnsResponse, err)
		if err != nil {
			return fmt.Errorf("[Azure CNS] Failed to create hnsNetwork %s err:%v", networkName, err)
		} else {
			hnsIDCustVNet = hnsResponse.Id
			log.Printf("[Azure CNS] Created network %s. hnsResponse: %+v", networkName, hnsResponse)
		}
	}

	// Create endpoint if it's not already present
	if ep, err := hcsshim.GetHNSEndpointByName(networkEpName); err != nil {
		var jsonPolicies []json.RawMessage
		outBoundNatPolicy := hcsshim.OutboundNatPolicy{}
		outBoundNatPolicy.Policy.Type = hcsshim.OutboundNat
		for _, ipAddress := range networkContainerInfo.CnetAddressSpace {
			outBoundNatPolicy.Exceptions = append(outBoundNatPolicy.Exceptions, ipAddress.IPAddress+"/"+strconv.Itoa(int(ipAddress.PrefixLength)))
		}

		if outBoundNatPolicy.Exceptions != nil {
			serializedOutboundNatPolicy, _ := json.Marshal(outBoundNatPolicy)
			jsonPolicies = append(jsonPolicies, serializedOutboundNatPolicy)
		}

		dnsList := "10.0.0.10,168.63.129.16" //TODO: Add DNS from cns.config too.
		hnsEndpoint := &hcsshim.HNSEndpoint{
			Name:           networkEpName,
			IPAddress:      ipAddr,
			VirtualNetwork: hnsIDCustVNet,
			// DNSSuffix: "ns1.svc.cluster.local", //TODO: This is coming from the nwConfig and not cns config
			DNSServerList: dnsList,
			Policies:      jsonPolicies,
		}

		// Marshal the request.
		buffer, err := json.Marshal(hnsEndpoint)
		if err != nil {
			return fmt.Errorf("[Azure CNS] Failed to marshal hnsEndpoint %s err:%v", networkEpName, err)
		}
		hnsRequest := string(buffer)

		// Create the HNS endpoint.
		log.Printf("[Azure CNS] HNSEndpointRequest POST request:%+v", hnsRequest)
		hnsResponse, err := hcsshim.HNSEndpointRequest("POST", "", hnsRequest)
		log.Printf("[Azure CNS] HNSEndpointRequest POST response:%+v err:%v.", hnsResponse, err)
		if err != nil {
			return fmt.Errorf("[Azure CNS] Failed to create hnsEndpoint %s err:%v", networkEpName, err)
		}

		log.Printf("[Azure CNS] Created endpoint %s. hnsResponse: %+v", networkEpName, hnsResponse)
	} else {
		log.Printf("[Azure CNS] Endpoint already exists: %s %+v", networkEpName, ep)
	}

	// Attach endpoint to the compartment
	cid := uint16(compartmentID)
	ep, _ := hcsshim.GetHNSEndpointByName(networkEpName)
	if err := ep.HostAttach(cid); err != nil {
		return fmt.Errorf("[Azure CNS] Failed to attach endpoint %s to compartment %d. err: %+v",
			networkEpName, compartmentID, err)
	}

	log.Printf("[Azure CNS] Successfully attached endpoint %s to compartment %d", networkEpName, compartmentID)

	// save the compartment state containing compartmentid and endpoint
	service.addCompartmentEndpoint(compartmentID, networkEpName)
	service.saveState()

	return nil
}

// detachNc detaches the endpoint for NC from host
func (service *HTTPRestService) detachNc(ncID string) error {
	log.Printf("[Azure CNS] Retrieve container state")
	containerID := "Swift_" + ncID
	containerStatus := service.state.ContainerStatus
	containerDetails, ok := containerStatus[containerID]
	if !ok {
		return fmt.Errorf("Network container: %s not found", ncID)
	}

	savedReq := containerDetails.CreateNetworkContainerRequest
	networkContainerInfo := cns.GetNetworkContainerResponse{
		IPConfiguration:            savedReq.IPConfiguration,
		Routes:                     savedReq.Routes,
		CnetAddressSpace:           savedReq.CnetAddressSpace,
		MultiTenancyInfo:           savedReq.MultiTenancyInfo,
		PrimaryInterfaceIdentifier: savedReq.PrimaryInterfaceIdentifier,
		LocalIPConfiguration:       savedReq.LocalIPConfiguration,
	}
	log.Printf("[Azure CNS] Retrieved network container state: %s %+v", containerID, networkContainerInfo)

	// validate the multitenancy info
	if networkContainerInfo.MultiTenancyInfo.EncapType != "Vlan" {
		return fmt.Errorf("Invalid multitenancy Encap type: %s. Expecting Vlan", networkContainerInfo.MultiTenancyInfo.EncapType)
	}

	if networkContainerInfo.MultiTenancyInfo.ID == 0 {
		return fmt.Errorf("Invalid multitenancy vlan id: %s", networkContainerInfo.MultiTenancyInfo.ID)
	}

	networkName := fmt.Sprintf("azure-vlanid%v", networkContainerInfo.MultiTenancyInfo.ID)
	_, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return fmt.Errorf("Cannot find the network to which the NC %s belongs to", ncID)
	}

	networkEpName := fmt.Sprintf("%s-%s", networkName, ncID)
	ep, err := hcsshim.GetHNSEndpointByName(networkEpName)
	if err != nil {
		return fmt.Errorf("Cannot find endpoint to which the NC %s belongs to", ncID)
	}

	if err := ep.HostDetach(); err != nil {
		return fmt.Errorf("[Azure CNS] Failed to detach endpoint %s. err: %+v", networkEpName, err)
	}

	log.Printf("[Azure CNS] Successfully detached endpoint %s", networkEpName)

	return nil
}

// Handles request to delete network container.
func (service *HTTPRestService) deleteCompartmentWithNCs(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteCompartmentWithNCs")

	returnCode := 0
	returnMessage := ""
	var req cns.DeleteCompartmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if _, err := os.Stat("./acn.exe"); err != nil {
		if os.IsNotExist(err) {
			log.Printf("[Azure CNS] Unable to find acn.exe. Cannot continue")
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Internal error managing compartment")
			returnCode = UnexpectedError
		}
	} else {
		if req.CompartmentID > 1 {
			if compartmentInfo, found := service.getCompartmentInfo(req.CompartmentID); found {
				for _, endpoint := range compartmentInfo {
					//delete endpoint
					ep, _ := hcsshim.GetHNSEndpointByName(endpoint)

					if err := ep.HostDetach(); err != nil {
						//return fmt.Errorf("[Azure CNS] Failed to detach endpoint %s. err: %+v", endpoint, err)
						log.Printf("[Azure CNS] Failed to detached endpoint %s due to error %v", endpoint, err)

					}

					log.Printf("[Azure CNS] Successfully detached endpoint %s", endpoint)

					// Delete the HNS endpoint.
					log.Printf("[Azure CNS] HNSEndpointRequest DELETE id:%v", ep.Id)
					hnsResponse, err := hcsshim.HNSEndpointRequest("DELETE", ep.Id, "")
					log.Printf("[Azure CNS] HNSEndpointRequest DELETE response:%+v err:%v.", hnsResponse, err)
				}

				//service.removeCompartmentInfo(req.CompartmentID)
			}

			args := []string{"/C", "acn.exe", "/operation", "delete", strconv.Itoa(req.CompartmentID)}
			log.Printf("[Azure CNS] Calling acn with args: %v", args)
			c := exec.Command("cmd", args...)
			if bytes, err := c.Output(); err != nil {
				log.Printf("[Azure CNS] Failure with acn. error: %s", bytes)
				returnMessage = fmt.Sprintf("%s", bytes)
				returnCode = UnexpectedError
			}
		} else {
			log.Printf("[Azure CNS] Invalid compartment id: %d", req.CompartmentID)
			returnMessage = fmt.Sprintf("[Azure CNS] Invalid compartment id: %d", req.CompartmentID)
			returnCode = InvalidParameter
		}
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

/*
// Handles request to delete windows network compartment.
func (service *HTTPRestService) deleteCompartment(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteCompartment")

	returnCode := 0
	returnMessage := ""
	var req cns.DeleteCompartmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if _, err := os.Stat("./acn.exe"); err != nil {
		if os.IsNotExist(err) {
			log.Printf("[Azure CNS] Unable to find acn.exe. Cannot continue")
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Internal error managing compartment")
			returnCode = UnexpectedError
		}
	} else {
		if req.CompartmentID > 1 {
			args := []string{"/C", "acn.exe", "/operation", "delete", strconv.Itoa(req.CompartmentID)}
			log.Printf("[Azure CNS] Calling acn with args: %v", args)
			c := exec.Command("cmd", args...)
			if bytes, err := c.Output(); err != nil {
				log.Printf("[Azure CNS] Failure with acn. error: %s", bytes)
				returnMessage = fmt.Sprintf("%s", bytes)
				returnCode = UnexpectedError
			}
		} else {
			log.Printf("[Azure CNS] Invalid compartment id: %d", req.CompartmentID)
			returnMessage = fmt.Sprintf("[Azure CNS] Invalid compartment id: %d", req.CompartmentID)
			returnCode = InvalidParameter
		}
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}*/

// Handles requests to create compartment with NCs.
func (service *HTTPRestService) createCompartmentWithNCs(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] createCompartmentWithNCs")

	returnCode := 0
	returnMessage := ""
	var req cns.CreateCompartmentWithNCsRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	var compartmentID int
	if _, err := os.Stat("./acn.exe"); err != nil {
		if os.IsNotExist(err) {
			log.Printf("[Azure CNS] Unable to find acn.exe. Cannot continue")
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Internal error managing compartment")
			returnCode = UnexpectedError
		}
	} else {
		//if len(req.NCIDs) == 1 {
		args := []string{"/C", "acn.exe", "/operation", "create"}
		log.Printf("[Azure CNS] Calling acn with args: %v", args)
		c := exec.Command("cmd", args...)
		if bytes, err := c.Output(); err == nil {
			if compartmentID, err = strconv.Atoi(strings.TrimSpace(string(bytes))); err != nil {
				log.Printf("[Azure CNS] Unable to parse output from acn.exe")
				returnMessage = fmt.Sprintf("[Azure CNS] Error. Internal error managing compartment")
				returnCode = UnexpectedError
			} else {
				returnMessage = "Successfully created network compartment"
				log.Printf("[Azure CNS] Successfully created network compartment %d", compartmentID)

				log.Printf("[Azure CNS] POST received for createCompartmentWithNCs with NCID count: %d, NCIDs: %+v",
					len(req.NCIDs), req.NCIDs)
				for _, ncid := range req.NCIDs {
					if err = service.setupNetworkAndEndpoints(ncid, compartmentID); err != nil {
						log.Printf("[Azure CNS] createCompartmentWithNCs failed due to error: %+v", err)
						returnCode = UnexpectedError

						// delete the created ncids and delete the compartment
					}
				}
			}
		} else {
			log.Printf("[Azure CNS] Failure with acn. error: %s", bytes)
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Internal error managing compartment")
			returnCode = UnexpectedError
		}
		/*} else {
			log.Printf("[Azure CNS] Invalid number of NCIDs: %d", len(req.NCIDs))
			returnMessage = fmt.Sprintf("[Azure CNS] Invalid number of NCIDs: %d", len(req.NCIDs))
			returnCode = InvalidParameter
		}*/
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	createCompartmentWithNCsResp := &cns.CreateCompartmentWithNCsResponse{Response: resp, CompartmentID: compartmentID}
	err = service.Listener.Encode(w, &createCompartmentWithNCsResp)
	log.Response(service.Name, createCompartmentWithNCsResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles requests to attach network compartment to NC.
func (service *HTTPRestService) attachNcToCompartment(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] attachNcToCompartment")

	returnCode := 0
	returnMessage := ""
	var req cns.AttachNcToCompartmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		returnMessage = fmt.Sprintf("[Azure CNS] Error. Unable to decode input request.")
		returnCode = InvalidParameter
	} else {
		switch r.Method {
		case "POST":
			log.Printf("[Azure CNS] POST received for attachNcToCompartment with NCID: %s CompartmentID: %d",
				req.NCID, req.CompartmentID)
			if err = service.setupNetworkAndEndpoints(req.NCID, req.CompartmentID); err != nil {
				log.Printf("[Azure CNS] attachNcToCompartment failed due to error: %+v", err)
				returnCode = UnexpectedError
			}
		default:
			returnMessage = "[Azure CNS] Error. attachNcToCompartment did not receive POST."
			returnCode = InvalidParameter
		}
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles requests to detach network compartment to NC.
func (service *HTTPRestService) detachNcFromCompartment(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] detachNcFromCompartment")

	returnCode := 0
	returnMessage := ""
	var req cns.DetachNcFromCompartmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		returnMessage = fmt.Sprintf("[Azure CNS] Error. Unable to decode input request.")
		returnCode = InvalidParameter
	} else {
		switch r.Method {
		case "POST":
			log.Printf("[Azure CNS] POST received for detachNcFromCompartment with NCID: %s", req.NCID)
			if err = service.detachNc(req.NCID); err != nil {
				log.Printf("[Azure CNS] detachNcFromCompartment failed due to error: %+v", err)
				returnCode = UnexpectedError
			}
		default:
			returnMessage = "[Azure CNS] Error. detachNcFromCompartment did not receive POST."
			returnCode = InvalidParameter
		}
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Stop stops the CNS.
func (service *HTTPRestService) Stop() {
	service.Uninitialize()
	log.Printf("[Azure CNS]  Service stopped.")
}

// Get dnc/service partition key
func (service *HTTPRestService) GetPartitionKey() (dncPartitionKey string) {
	service.lock.Lock()
	dncPartitionKey = service.dncPartitionKey
	service.lock.Unlock()
	return
}

// Handles requests to set the environment type.
func (service *HTTPRestService) setEnvironment(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] setEnvironment")

	var req cns.SetEnvironmentRequest
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		log.Printf("[Azure CNS]  POST received for SetEnvironment.")
		service.state.Location = req.Location
		service.state.NetworkType = req.NetworkType
		service.state.Initialized = true
		service.saveState()
	default:
	}

	resp := &cns.Response{ReturnCode: 0}
	err = service.Listener.Encode(w, &resp)

	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles CreateNetwork requests.
func (service *HTTPRestService) createNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] createNetwork")

	var err error
	returnCode := 0
	returnMessage := ""

	if service.state.Initialized {
		var req cns.CreateNetworkRequest
		err = service.Listener.Decode(w, r, &req)
		log.Request(service.Name, &req, err)

		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. Unable to decode input request.")
			returnCode = InvalidParameter
		} else {
			switch r.Method {
			case "POST":
				dc := service.dockerClient
				rt := service.routingTable
				err = dc.NetworkExists(req.NetworkName)

				// Network does not exist.
				if err != nil {
					switch service.state.NetworkType {
					case "Underlay":
						switch service.state.Location {
						case "Azure":
							log.Printf("[Azure CNS] Goign to create network with name %v.", req.NetworkName)

							err = rt.GetRoutingTable()
							if err != nil {
								// We should not fail the call to create network for this.
								// This is because restoring routes is a fallback mechanism in case
								// network driver is not behaving as expected.
								// The responsibility to restore routes is with network driver.
								log.Printf("[Azure CNS] Unable to get routing table from node, %+v.", err.Error())
							}

							nicInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromHost()
							if err != nil {
								returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryInterfaceInfoFromHost failed %v.", err.Error())
								returnCode = UnexpectedError
								break
							}

							err = dc.CreateNetwork(req.NetworkName, nicInfo, req.Options)
							if err != nil {
								returnMessage = fmt.Sprintf("[Azure CNS] Error. CreateNetwork failed %v.", err.Error())
								returnCode = UnexpectedError
							}

							err = rt.RestoreRoutingTable()
							if err != nil {
								log.Printf("[Azure CNS] Unable to restore routing table on node, %+v.", err.Error())
							}

							networkInfo := &networkInfo{
								NetworkName: req.NetworkName,
								NicInfo:     nicInfo,
								Options:     req.Options,
							}

							service.state.Networks[req.NetworkName] = networkInfo

						case "StandAlone":
							returnMessage = fmt.Sprintf("[Azure CNS] Error. Underlay network is not supported in StandAlone environment. %v.", err.Error())
							returnCode = UnsupportedEnvironment
						}
					case "Overlay":
						returnMessage = fmt.Sprintf("[Azure CNS] Error. Overlay support not yet available. %v.", err.Error())
						returnCode = UnsupportedEnvironment
					}
				} else {
					returnMessage = fmt.Sprintf("[Azure CNS] Received a request to create an already existing network %v", req.NetworkName)
					log.Printf(returnMessage)
				}

			default:
				returnMessage = "[Azure CNS] Error. CreateNetwork did not receive a POST."
				returnCode = InvalidParameter
			}
		}

	} else {
		returnMessage = fmt.Sprintf("[Azure CNS] Error. CNS is not yet initialized with environment.")
		returnCode = UnsupportedEnvironment
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)

	if returnCode == 0 {
		service.saveState()
	}

	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles DeleteNetwork requests.
func (service *HTTPRestService) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteNetwork")

	var req cns.DeleteNetworkRequest
	returnCode := 0
	returnMessage := ""
	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	switch r.Method {
	case "POST":
		dc := service.dockerClient
		err := dc.NetworkExists(req.NetworkName)

		// Network does exist
		if err == nil {
			log.Printf("[Azure CNS] Goign to delete network with name %v.", req.NetworkName)
			err := dc.DeleteNetwork(req.NetworkName)
			if err != nil {
				returnMessage = fmt.Sprintf("[Azure CNS] Error. DeleteNetwork failed %v.", err.Error())
				returnCode = UnexpectedError
			}
		} else {
			if err == fmt.Errorf("Network not found") {
				log.Printf("[Azure CNS] Received a request to delete network that does not exist: %v.", req.NetworkName)
			} else {
				returnCode = UnexpectedError
				returnMessage = err.Error()
			}
		}

	default:
		returnMessage = "[Azure CNS] Error. DeleteNetwork did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := &cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)

	if returnCode == 0 {
		delete(service.state.Networks, req.NetworkName)
		service.saveState()
	}

	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles ip reservation requests.
func (service *HTTPRestService) reserveIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] reserveIPAddress")

	var req cns.ReserveIPAddressRequest
	returnMessage := ""
	returnCode := 0
	addr := ""
	address := ""
	err := service.Listener.Decode(w, r, &req)

	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.ReservationID == "" {
		returnCode = ReservationNotFound
		returnMessage = fmt.Sprintf("[Azure CNS] Error. ReservationId is empty")
	}

	switch r.Method {
	case "POST":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		addr, err = ic.ReserveIPAddress(poolID, req.ReservationID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ReserveIpAddress failed with %+v", err.Error())
			returnCode = AddressUnavailable
			break
		}

		addressIP, _, err := net.ParseCIDR(addr)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ParseCIDR failed with %+v", err.Error())
			returnCode = UnexpectedError
			break
		}
		address = addressIP.String()

	default:
		returnMessage = "[Azure CNS] Error. ReserveIP did not receive a POST."
		returnCode = InvalidParameter

	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.ReserveIPAddressResponse{Response: resp, IPAddress: address}
	err = service.Listener.Encode(w, &reserveResp)
	log.Response(service.Name, reserveResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles release ip reservation requests.
func (service *HTTPRestService) releaseIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] releaseIPAddress")

	var req cns.ReleaseIPAddressRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)

	if err != nil {
		return
	}

	if req.ReservationID == "" {
		returnCode = ReservationNotFound
		returnMessage = fmt.Sprintf("[Azure CNS] Error. ReservationId is empty")
	}

	switch r.Method {
	case "POST":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		err = ic.ReleaseIPAddress(poolID, req.ReservationID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] ReleaseIpAddress failed with %+v", err.Error())
			returnCode = ReservationNotFound
		}

	default:
		returnMessage = "[Azure CNS] Error. ReleaseIP did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Retrieves the host local ip address. Containers can talk to host using this IP address.
func (service *HTTPRestService) getHostLocalIP(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getHostLocalIP")
	log.Request(service.Name, "getHostLocalIP", nil)

	var found bool
	var errmsg string
	hostLocalIP := "0.0.0.0"

	if service.state.Initialized {
		switch r.Method {
		case "GET":
			switch service.state.NetworkType {
			case "Underlay":
				if service.imdsClient != nil {
					piface, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
					if err == nil {
						hostLocalIP = piface.PrimaryIP
						found = true
					} else {
						log.Printf("[Azure-CNS] Received error from GetPrimaryInterfaceInfoFromMemory. err: %v", err.Error())
					}
				}

			case "Overlay":
				errmsg = "[Azure-CNS] Overlay is not yet supported."
			}

		default:
			errmsg = "[Azure-CNS] GetHostLocalIP API expects a GET."
		}
	}

	returnCode := 0
	if !found {
		returnCode = NotFound
		if errmsg == "" {
			errmsg = "[Azure-CNS] Unable to get host local ip. Check if environment is initialized.."
		}
	}

	resp := cns.Response{ReturnCode: returnCode, Message: errmsg}
	hostLocalIPResponse := &cns.HostLocalIPAddressResponse{
		Response:  resp,
		IPAddress: hostLocalIP,
	}

	err := service.Listener.Encode(w, &hostLocalIPResponse)

	log.Response(service.Name, hostLocalIPResponse, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles ip address utilization requests.
func (service *HTTPRestService) getIPAddressUtilization(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getIPAddressUtilization")
	log.Request(service.Name, "getIPAddressUtilization", nil)

	returnMessage := ""
	returnCode := 0
	capacity := 0
	available := 0
	var unhealthyAddrs []string

	switch r.Method {
	case "GET":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		capacity, available, unhealthyAddrs, err = ic.GetIPAddressUtilization(poolID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetIPUtilization failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}
		log.Printf("[Azure CNS] Capacity %v Available %v UnhealthyAddrs %v", capacity, available, unhealthyAddrs)

	default:
		returnMessage = "[Azure CNS] Error. GetIPUtilization did not receive a GET."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	utilResponse := &cns.IPAddressesUtilizationResponse{
		Response:  resp,
		Available: available,
		Reserved:  capacity - available,
		Unhealthy: len(unhealthyAddrs),
	}

	err := service.Listener.Encode(w, &utilResponse)
	log.Response(service.Name, utilResponse, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles retrieval of ip addresses that are available to be reserved from ipam driver.
func (service *HTTPRestService) getAvailableIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getAvailableIPAddresses")
	log.Request(service.Name, "getAvailableIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles retrieval of reserved ip addresses from ipam driver.
func (service *HTTPRestService) getReservedIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getReservedIPAddresses")
	log.Request(service.Name, "getReservedIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles retrieval of ghost ip addresses from ipam driver.
func (service *HTTPRestService) getUnhealthyIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getUnhealthyIPAddresses")
	log.Request(service.Name, "getUnhealthyIPAddresses", nil)

	returnMessage := ""
	returnCode := 0
	capacity := 0
	available := 0
	var unhealthyAddrs []string

	switch r.Method {
	case "GET":
		ic := service.ipamClient

		ifInfo, err := service.imdsClient.GetPrimaryInterfaceInfoFromMemory()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPrimaryIfaceInfo failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		asID, err := ic.GetAddressSpace()
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetAddressSpace failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		poolID, err := ic.GetPoolID(asID, ifInfo.Subnet)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetPoolID failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}

		capacity, available, unhealthyAddrs, err = ic.GetIPAddressUtilization(poolID)
		if err != nil {
			returnMessage = fmt.Sprintf("[Azure CNS] Error. GetIPUtilization failed %v", err.Error())
			returnCode = UnexpectedError
			break
		}
		log.Printf("[Azure CNS] Capacity %v Available %v UnhealthyAddrs %v", capacity, available, unhealthyAddrs)

	default:
		returnMessage = "[Azure CNS] Error. GetUnhealthyIP did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	ipResp := &cns.GetIPAddressesResponse{
		Response:    resp,
		IPAddresses: unhealthyAddrs,
	}

	err := service.Listener.Encode(w, &ipResp)
	log.Response(service.Name, ipResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// getAllIPAddresses retrieves all ip addresses from ipam driver.
func (service *HTTPRestService) getAllIPAddresses(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getAllIPAddresses")
	log.Request(service.Name, "getAllIPAddresses", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := cns.Response{ReturnCode: 0}
	ipResp := &cns.GetIPAddressesResponse{Response: resp}
	err := service.Listener.Encode(w, &ipResp)

	log.Response(service.Name, ipResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// Handles health report requests.
func (service *HTTPRestService) getHealthReport(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getHealthReport")
	log.Request(service.Name, "getHealthReport", nil)

	switch r.Method {
	case "GET":
	default:
	}

	resp := &cns.Response{ReturnCode: 0}
	err := service.Listener.Encode(w, &resp)

	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// saveState writes CNS state to persistent store.
func (service *HTTPRestService) saveState() error {
	log.Printf("[Azure CNS] saveState")

	// Skip if a store is not provided.
	if service.store == nil {
		log.Printf("[Azure CNS]  store not initialized.")
		return nil
	}

	// Update time stamp.
	service.state.TimeStamp = time.Now()
	err := service.store.Write(storeKey, &service.state)
	if err == nil {
		log.Printf("[Azure CNS]  State saved successfully.\n")
	} else {
		log.Errorf("[Azure CNS]  Failed to save state., err:%v\n", err)
	}

	return err
}

// restoreState restores CNS state from persistent store.
func (service *HTTPRestService) restoreState() error {
	log.Printf("[Azure CNS] restoreState")

	// Skip if a store is not provided.
	if service.store == nil {
		log.Printf("[Azure CNS]  store not initialized.")
		return nil
	}

	// Read any persisted state.
	err := service.store.Read(storeKey, &service.state)
	if err != nil {
		if err == store.ErrKeyNotFound {
			// Nothing to restore.
			log.Printf("[Azure CNS]  No state to restore.\n")
			return nil
		}

		log.Errorf("[Azure CNS]  Failed to restore state, err:%v\n", err)
		return err
	}

	log.Printf("[Azure CNS]  Restored state, %+v\n", service.state)
	return nil
}

func (service *HTTPRestService) setOrchestratorType(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] setOrchestratorType")

	var req cns.SetOrchestratorTypeRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	if err != nil {
		return
	}

	service.lock.Lock()

	service.dncPartitionKey = req.DncPartitionKey

	switch req.OrchestratorType {
	case cns.ServiceFabric:
		fallthrough
	case cns.Kubernetes:
		fallthrough
	case cns.WebApps:
		fallthrough
	case cns.Batch:
		fallthrough
	case cns.DBforPostgreSQL:
		fallthrough
	case cns.AzureFirstParty:
		service.state.OrchestratorType = req.OrchestratorType
		service.saveState()
	default:
		returnMessage = fmt.Sprintf("Invalid Orchestrator type %v", req.OrchestratorType)
		returnCode = UnsupportedOrchestratorType
	}

	service.lock.Unlock()

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	err = service.Listener.Encode(w, &resp)
	log.Response(service.Name, resp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) saveNetworkContainerGoalState(req cns.CreateNetworkContainerRequest) (int, string) {
	// we don't want to overwrite what other calls may have written
	service.lock.Lock()
	defer service.lock.Unlock()

	existing, ok := service.state.ContainerStatus[req.NetworkContainerid]
	var hostVersion string
	if ok {
		hostVersion = existing.HostVersion
	}

	if service.state.ContainerStatus == nil {
		service.state.ContainerStatus = make(map[string]containerstatus)
	}

	service.state.ContainerStatus[req.NetworkContainerid] =
		containerstatus{
			ID:                            req.NetworkContainerid,
			VMVersion:                     req.Version,
			CreateNetworkContainerRequest: req,
			HostVersion:                   hostVersion}

	switch req.NetworkContainerType {
	case cns.AzureContainerInstance:
		fallthrough
	case cns.ClearContainer:
		fallthrough
	case cns.Docker:
		fallthrough
	case cns.Basic:
		switch service.state.OrchestratorType {
		case cns.Kubernetes:
			fallthrough
		case cns.ServiceFabric:
			fallthrough
		case cns.Batch:
			fallthrough
		case cns.DBforPostgreSQL:
			fallthrough
		case cns.AzureFirstParty:
			var podInfo cns.KubernetesPodInfo
			err := json.Unmarshal(req.OrchestratorContext, &podInfo)
			if err != nil {
				errBuf := fmt.Sprintf("Unmarshalling %s failed with error %v", req.NetworkContainerType, err)
				return UnexpectedError, errBuf
			}

			log.Printf("Pod info %v", podInfo)

			if service.state.ContainerIDByOrchestratorContext == nil {
				service.state.ContainerIDByOrchestratorContext = make(map[string]string)
			}

			service.state.ContainerIDByOrchestratorContext[podInfo.PodName+podInfo.PodNamespace] = req.NetworkContainerid
			break

		default:
			log.Printf("Invalid orchestrator type %v", service.state.OrchestratorType)
		}
	}

	service.saveState()
	return 0, ""
}

func (service *HTTPRestService) createOrUpdateNetworkContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] createOrUpdateNetworkContainer")

	var req cns.CreateNetworkContainerRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	}

	switch r.Method {
	case "POST":
		if req.NetworkContainerType == cns.WebApps {
			// try to get the saved nc state if it exists
			service.lock.Lock()
			existing, ok := service.state.ContainerStatus[req.NetworkContainerid]
			service.lock.Unlock()

			// create/update nc only if it doesn't exist or it exists and the requested version is different from the saved version
			if !ok || (ok && existing.VMVersion != req.Version) {
				nc := service.networkContainer
				if err = nc.Create(req); err != nil {
					returnMessage = fmt.Sprintf("[Azure CNS] Error. CreateOrUpdateNetworkContainer failed %v", err.Error())
					returnCode = UnexpectedError
					break
				}
			}
		} else if req.NetworkContainerType == cns.AzureContainerInstance {
			// try to get the saved nc state if it exists
			service.lock.Lock()
			existing, ok := service.state.ContainerStatus[req.NetworkContainerid]
			service.lock.Unlock()

			// create/update nc only if it doesn't exist or it exists and the requested version is different from the saved version
			if ok && existing.VMVersion != req.Version {
				nc := service.networkContainer
				pluginBinPath, _ := service.GetOption(acn.OptCNIPath).(string)
				configPath, _ := service.GetOption(acn.OptCNIConfigFile).(string)
				netPluginConfig := networkcontainers.NewNetPluginConfiguration(pluginBinPath, configPath)
				if err = nc.Update(req, netPluginConfig); err != nil {
					returnMessage = fmt.Sprintf("[Azure CNS] Error. CreateOrUpdateNetworkContainer failed %v", err.Error())
					returnCode = UnexpectedError
					break
				}
			}
		}

		returnCode, returnMessage = service.saveNetworkContainerGoalState(req)

	default:
		returnMessage = "[Azure CNS] Error. CreateOrUpdateNetworkContainer did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.CreateNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)
	log.Response(service.Name, reserveResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) getNetworkContainerByID(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getNetworkContainerByID")

	var req cns.GetNetworkContainerRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.GetNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)
	log.Response(service.Name, reserveResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) getNetworkContainerResponse(req cns.GetNetworkContainerRequest) cns.GetNetworkContainerResponse {
	var containerID string
	var getNetworkContainerResponse cns.GetNetworkContainerResponse

	service.lock.Lock()
	defer service.lock.Unlock()

	switch service.state.OrchestratorType {
	case cns.Kubernetes:
		fallthrough
	case cns.ServiceFabric:
		fallthrough
	case cns.Batch:
		fallthrough
	case cns.DBforPostgreSQL:
		fallthrough
	case cns.AzureFirstParty:
		var podInfo cns.KubernetesPodInfo
		err := json.Unmarshal(req.OrchestratorContext, &podInfo)
		if err != nil {
			getNetworkContainerResponse.Response.ReturnCode = UnexpectedError
			getNetworkContainerResponse.Response.Message = fmt.Sprintf("Unmarshalling orchestrator context failed with error %v", err)
			return getNetworkContainerResponse
		}

		log.Printf("pod info %+v", podInfo)
		containerID = service.state.ContainerIDByOrchestratorContext[podInfo.PodName+podInfo.PodNamespace]
		log.Printf("containerid %v", containerID)
		break

	default:
		getNetworkContainerResponse.Response.ReturnCode = UnsupportedOrchestratorType
		getNetworkContainerResponse.Response.Message = fmt.Sprintf("Invalid orchestrator type %v", service.state.OrchestratorType)
		return getNetworkContainerResponse
	}

	containerStatus := service.state.ContainerStatus
	containerDetails, ok := containerStatus[containerID]
	if !ok {
		getNetworkContainerResponse.Response.ReturnCode = UnknownContainerID
		getNetworkContainerResponse.Response.Message = "NetworkContainer doesn't exist."
		return getNetworkContainerResponse
	}

	savedReq := containerDetails.CreateNetworkContainerRequest
	getNetworkContainerResponse = cns.GetNetworkContainerResponse{
		IPConfiguration:            savedReq.IPConfiguration,
		Routes:                     savedReq.Routes,
		CnetAddressSpace:           savedReq.CnetAddressSpace,
		MultiTenancyInfo:           savedReq.MultiTenancyInfo,
		PrimaryInterfaceIdentifier: savedReq.PrimaryInterfaceIdentifier,
		LocalIPConfiguration:       savedReq.LocalIPConfiguration,
	}

	return getNetworkContainerResponse
}

func (service *HTTPRestService) getNetworkContainerByOrchestratorContext(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getNetworkContainerByOrchestratorContext")

	var req cns.GetNetworkContainerRequest

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	getNetworkContainerResponse := service.getNetworkContainerResponse(req)
	returnCode := getNetworkContainerResponse.Response.ReturnCode
	err = service.Listener.Encode(w, &getNetworkContainerResponse)
	log.Response(service.Name, getNetworkContainerResponse, returnCode, ReturnCodeToString(returnCode), err)
}

func (service *HTTPRestService) deleteNetworkContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] deleteNetworkContainer")

	var req cns.DeleteNetworkContainerRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	}

	switch r.Method {
	case "POST":
		var containerStatus containerstatus
		var ok bool

		service.lock.Lock()
		containerStatus, ok = service.state.ContainerStatus[req.NetworkContainerid]
		service.lock.Unlock()

		if !ok {
			log.Printf("Not able to retrieve network container details for this container id %v", req.NetworkContainerid)
			break
		}

		if containerStatus.CreateNetworkContainerRequest.NetworkContainerType == cns.WebApps {
			nc := service.networkContainer
			if err := nc.Delete(req.NetworkContainerid); err != nil {
				returnMessage = fmt.Sprintf("[Azure CNS] Error. DeleteNetworkContainer failed %v", err.Error())
				returnCode = UnexpectedError
				break
			}
		}

		service.lock.Lock()
		defer service.lock.Unlock()

		if service.state.ContainerStatus != nil {
			delete(service.state.ContainerStatus, req.NetworkContainerid)
		}

		if service.state.ContainerIDByOrchestratorContext != nil {
			for orchestratorContext, networkContainerID := range service.state.ContainerIDByOrchestratorContext {
				if networkContainerID == req.NetworkContainerid {
					delete(service.state.ContainerIDByOrchestratorContext, orchestratorContext)
					break
				}
			}
		}

		service.saveState()
		break
	default:
		returnMessage = "[Azure CNS] Error. DeleteNetworkContainer did not receive a POST."
		returnCode = InvalidParameter
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	reserveResp := &cns.DeleteNetworkContainerResponse{Response: resp}
	err = service.Listener.Encode(w, &reserveResp)
	log.Response(service.Name, reserveResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) getNetworkContainerStatus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getNetworkContainerStatus")

	var req cns.GetNetworkContainerStatusRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	service.lock.Lock()
	defer service.lock.Unlock()
	var ok bool
	var containerDetails containerstatus

	containerInfo := service.state.ContainerStatus
	if containerInfo != nil {
		containerDetails, ok = containerInfo[req.NetworkContainerid]
	} else {
		ok = false
	}

	var hostVersion string
	var vmVersion string

	if ok {
		savedReq := containerDetails.CreateNetworkContainerRequest
		containerVersion, err := service.imdsClient.GetNetworkContainerInfoFromHost(
			req.NetworkContainerid,
			savedReq.PrimaryInterfaceIdentifier,
			savedReq.AuthorizationToken, swiftAPIVersion)

		if err != nil {
			returnCode = CallToHostFailed
			returnMessage = err.Error()
		} else {
			hostVersion = containerVersion.ProgrammedVersion
		}
	} else {
		returnMessage = "[Azure CNS] Never received call to create this container."
		returnCode = UnknownContainerID
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	networkContainerStatusReponse := cns.GetNetworkContainerStatusResponse{
		Response:           resp,
		NetworkContainerid: req.NetworkContainerid,
		AzureHostVersion:   hostVersion,
		Version:            vmVersion,
	}

	err = service.Listener.Encode(w, &networkContainerStatusReponse)
	log.Response(service.Name, networkContainerStatusReponse, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) getInterfaceForContainer(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] getInterfaceForContainer")

	var req cns.GetInterfaceForContainerRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	containerInfo := service.state.ContainerStatus
	containerDetails, ok := containerInfo[req.NetworkContainerID]
	var interfaceName string
	var ipaddress string
	var cnetSpace []cns.IPSubnet
	var dnsServers []string
	var version string

	if ok {
		savedReq := containerDetails.CreateNetworkContainerRequest
		interfaceName = savedReq.NetworkContainerid
		cnetSpace = savedReq.CnetAddressSpace
		ipaddress = savedReq.IPConfiguration.IPSubnet.IPAddress // it has to exist
		dnsServers = savedReq.IPConfiguration.DNSServers
		version = savedReq.Version
	} else {
		returnMessage = "[Azure CNS] Never received call to create this container."
		returnCode = UnknownContainerID
		interfaceName = ""
		ipaddress = ""
		version = ""
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	getInterfaceForContainerResponse := cns.GetInterfaceForContainerResponse{
		Response:                resp,
		NetworkInterface:        cns.NetworkInterface{Name: interfaceName, IPAddress: ipaddress},
		CnetAddressSpace:        cnetSpace,
		DNSServers:              dnsServers,
		NetworkContainerVersion: version,
	}

	err = service.Listener.Encode(w, &getInterfaceForContainerResponse)

	log.Response(service.Name, getInterfaceForContainerResponse, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

// restoreNetworkState restores Network state that existed before reboot.
func (service *HTTPRestService) restoreNetworkState() error {
	log.Printf("[Azure CNS] Enter Restoring Network State")

	if service.store == nil {
		log.Printf("[Azure CNS] Store is not initialized, nothing to restore for network state.")
		return nil
	}

	rebooted := false
	modTime, err := service.store.GetModificationTime()

	if err == nil {
		log.Printf("[Azure CNS] Store timestamp is %v.", modTime)

		rebootTime, err := platform.GetLastRebootTime()
		if err == nil && rebootTime.After(modTime) {
			log.Printf("[Azure CNS] reboot time %v mod time %v", rebootTime, modTime)
			rebooted = true
		}
	}

	if rebooted {
		for _, nwInfo := range service.state.Networks {
			enableSnat := true

			log.Printf("[Azure CNS] Restore nwinfo %v", nwInfo)

			if nwInfo.Options != nil {
				if _, ok := nwInfo.Options[dockerclient.OptDisableSnat]; ok {
					enableSnat = false
				}
			}

			if enableSnat {
				err := platform.SetOutboundSNAT(nwInfo.NicInfo.Subnet)
				if err != nil {
					log.Printf("[Azure CNS] Error setting up SNAT outbound rule %v", err)
					return err
				}
			}
		}
	}

	return nil
}

func (service *HTTPRestService) attachNetworkContainerToNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] attachNetworkContainerToNetwork")

	var req cns.ConfigureContainerNetworkingRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	if req.Containerid == "" {
		returnCode = DockerContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. Containerid is empty")
	} else if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	} else {
		switch r.Method {
		case "POST":
			// try to get the saved nc state if it exists
			service.lock.Lock()
			existing, ok := service.state.ContainerStatus[cns.SwiftPrefix+req.NetworkContainerid]
			service.lock.Unlock()
			if !ok {
				returnMessage = fmt.Sprintf("[Azure CNS] Error. Network Container %s does not exist.", req.NetworkContainerid)
				returnCode = NotFound
			} else {
				var podInfo cns.KubernetesPodInfo
				err := json.Unmarshal(existing.CreateNetworkContainerRequest.OrchestratorContext, &podInfo)
				if err != nil {
					returnCode = UnexpectedError
					returnMessage = fmt.Sprintf("Unmarshalling orchestrator context failed with error %+v", err)
				} else {
					nc := service.networkContainer
					pluginBinPath, _ := service.GetOption(acn.OptCNIPath).(string)
					configPath, _ := service.GetOption(acn.OptCNIConfigFile).(string)
					netPluginConfig := networkcontainers.NewNetPluginConfiguration(pluginBinPath, configPath)
					if err = nc.Attach(podInfo.PodName, podInfo.PodNamespace, req.Containerid, netPluginConfig); err != nil {
						returnMessage = fmt.Sprintf("[Azure CNS] Error. AttachContainerToNetwork failed %+v", err.Error())
						returnCode = UnexpectedError
					}
				}
			}

		default:
			returnMessage = "[Azure CNS] Error. AttachContainerToNetwork did not receive a POST."
			returnCode = InvalidParameter
		}
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	attachResp := &cns.AttachContainerToNetworkResponse{Response: resp}
	err = service.Listener.Encode(w, &attachResp)
	log.Response(service.Name, attachResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}

func (service *HTTPRestService) detachNetworkContainerFromNetwork(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Azure CNS] detachNetworkContainerFromNetwork")

	var req cns.ConfigureContainerNetworkingRequest
	returnMessage := ""
	returnCode := 0

	err := service.Listener.Decode(w, r, &req)
	log.Request(service.Name, &req, err)
	if err != nil {
		return
	}

	if req.Containerid == "" {
		returnCode = DockerContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. Containerid is empty")
	} else if req.NetworkContainerid == "" {
		returnCode = NetworkContainerNotSpecified
		returnMessage = fmt.Sprintf("[Azure CNS] Error. NetworkContainerid is empty")
	} else {
		switch r.Method {
		case "POST":
			// try to get the saved nc state if it exists
			service.lock.Lock()
			existing, ok := service.state.ContainerStatus[cns.SwiftPrefix+req.NetworkContainerid]
			service.lock.Unlock()
			if !ok {
				returnMessage = fmt.Sprintf("[Azure CNS] Error. Network Container %s does not exist.", req.NetworkContainerid)
				returnCode = NotFound
			} else {
				var podInfo cns.KubernetesPodInfo
				err := json.Unmarshal(existing.CreateNetworkContainerRequest.OrchestratorContext, &podInfo)
				if err != nil {
					returnCode = UnexpectedError
					returnMessage = fmt.Sprintf("Unmarshalling orchestrator context failed with error %+v", err)
				} else {
					nc := service.networkContainer
					pluginBinPath, _ := service.GetOption(acn.OptCNIPath).(string)
					configPath, _ := service.GetOption(acn.OptCNIConfigFile).(string)
					netPluginConfig := networkcontainers.NewNetPluginConfiguration(pluginBinPath, configPath)
					if err = nc.Detach(podInfo.PodName, podInfo.PodNamespace, req.Containerid, netPluginConfig); err != nil {
						returnMessage = fmt.Sprintf("[Azure CNS] Error. detachNetworkContainerFromNetwork failed %+v", err.Error())
						returnCode = UnexpectedError
					}
				}
			}

		default:
			returnMessage = "[Azure CNS] Error. detachNetworkContainerFromNetwork did not receive a POST."
			returnCode = InvalidParameter
		}
	}

	resp := cns.Response{
		ReturnCode: returnCode,
		Message:    returnMessage,
	}

	detachResp := &cns.DetachContainerFromNetworkResponse{Response: resp}
	err = service.Listener.Encode(w, &detachResp)
	log.Response(service.Name, detachResp, resp.ReturnCode, ReturnCodeToString(resp.ReturnCode), err)
}
