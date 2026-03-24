package dhcpserver

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Rotchamar/dhcp/dhcpv4"
	"github.com/Rotchamar/dhcp/dhcpv4/server4"
)

// Reserved Ips
var reservedIPs = map[string]struct{}{
	//  ── subnet 10.2.0.0/26  (UE1 + AGF1) ──────────────────
	"10.2.0.1": {}, "10.2.0.2": {}, "10.2.0.3": {}, // UE-1
	"10.2.0.22": {}, "10.2.0.23": {}, "10.2.0.24": {}, // AGF-1
	//  ── subnet 10.2.0.64/26 (UE2 + AGF2) ─────────────────
	"10.2.0.64": {}, "10.2.0.65": {}, "10.2.0.66": {}, // UE-2
	"10.2.0.84": {}, "10.2.0.85": {}, "10.2.0.86": {}, // AGF-2
}

var DHCPClients Clients
var EthConn EthSocketConn

//TODO: check whether is still needed
// Mutex y global to pass T-GNBiD
//var (
//	globalTargetGnb string
//	mu              sync.RWMutex
//)

// Subnet and offset params
var (
	// IP base for GNB ID using whole subnets
	subnetRanges = map[string]*net.IPNet{} //subnet /26 for each AGF

	// For each GNB, next offset (0,1,2,…)
	nextOffset = make(map[string]uint32)
	// startings offsets inside each subnet:
	startOffset = map[string]uint32{
		"000102": 4, // 10.2.0.0 + 4  → 10.2.0.4
		"000103": 3, // 10.2.0.64 + 3 → 10.2.0.67
	}
	muOffsets sync.Mutex

	// Last assigned IP
	assignedIP   net.IP
	assignedIPMu sync.RWMutex
)

// Subnets start
func init() {
	// We define desired subnets
	//10.2.0.0/26  10.2.0.1 – 10.2.0.62  10.2.0.63 (broadcast) for connection UE1-AG1
	//10.2.0.64/26 10.2.0.65 – 10.2.0.126 10.2.0.127 (broadcast) for connection UE2-AGF2

	subnets := map[string]string{
		"000102": "10.2.0.0/26",
		"000103": "10.2.0.64/26",
	}

	for gnb, cidr := range subnets {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("Error parsing CIDR %s for GNB %s: %v", cidr, gnb, err)
		}
		subnetRanges[gnb] = ipnet
	}
}

func DecideIP(targetGnbID string) {
	muOffsets.Lock()
	defer muOffsets.Unlock()

	ipnet, ok := subnetRanges[targetGnbID]
	if !ok {
		log.Printf("Subnet unknown for GNB %s", targetGnbID)
		assignedIP = net.IPv4(10, 255, 255, 254) // Default-value
		return
	}

	base := startOffset[targetGnbID]      // Where starts
	network := ipnet.IP.Mask(ipnet.Mask)  // network addres
	startIP := incrementIP(network, base) // First allowed IP

	for {
		candidate := incrementIP(startIP, nextOffset[targetGnbID])

		switch {
		case !ipInSubnet(candidate, ipnet) || isBroadcast(candidate, ipnet):
			log.Printf("No IPs left on subnet %s", targetGnbID)
			assignedIP = net.IPv4(10, 255, 255, 254)
			return

		case isReserved(candidate):
			nextOffset[targetGnbID]++
			continue

		default:
			assignedIP = candidate
			nextOffset[targetGnbID]++
			log.Printf("[DecideIP] GNB %s → %s", targetGnbID, candidate)
			return
		}
	}
}

// Gets assigned Ip from last call to DecideIP
func GetAssignedIP() net.IP {
	assignedIPMu.RLock()
	defer assignedIPMu.RUnlock()
	log.Printf("[GetAssignedIP] MSR Devolviendo IP asignada: %s", assignedIP.String())
	return assignedIP
}

// Adds nextOffset to Ip value
func incrementIP(ip net.IP, n uint32) net.IP {
	ip = ip.To4()
	val := binary.BigEndian.Uint32(ip)
	val += n
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], val)
	return net.IP(buf[:])
}
func isBroadcast(ip net.IP, subnet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	mask := binary.BigEndian.Uint32(subnet.Mask)
	network := binary.BigEndian.Uint32(subnet.IP)
	broadcast := network | (^mask)
	return binary.BigEndian.Uint32(ip4) == broadcast
}

// ipInSubnet checks whether IP is in the subnet
func ipInSubnet(ip net.IP, subnet *net.IPNet) bool {
	return subnet.Contains(ip)
}

// isReserved returns true if IP is in ReservedIps
func isReserved(ip net.IP) bool {
	_, ok := reservedIPs[ip.String()]
	return ok
}

// func setGlobalTargetGnb(id string) {
// 	mu.Lock()
// 	globalTargetGnb = id
// 	mu.Unlock()
// }

func StartDHCPServer(interfaceName string) {
	var err error

	DHCPClients.Value = make(map[[6]byte]ClientInfo)

	EthConn, err = NewEthSocketConn(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	ServerIP, err = GetInterfaceIpv4Addr(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: dhcpv4.ServerPort}
	server, err := server4.NewServer(interfaceName, laddr, handlerDHCP, server4.WithDebugLogger())
	if err != nil {
		log.Fatal(err)
	}

	log.Println(" DHCP Server running in UDP port:67")
	server.Serve()
}

func TriggerDHCPClient(ueIP string, targetGnbID string) error {
	//setGlobalTargetGnb(targetGnbID)
	DecideIP(targetGnbID)

	url := fmt.Sprintf("http://%s:8081/dhcp/start", ueIP)
	log.Printf("[TriggerDHCPClient] Preparing GET a: %s", url)

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("[TriggerDHCPClient] Error sendind GET to :%s: %w", url, err)
	}
	defer resp.Body.Close()

	log.Printf("[TriggerDHCPClient] HTTP response: %s", resp.Status)
	return nil
}
