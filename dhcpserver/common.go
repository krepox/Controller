package dhcpserver

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/Rotchamar/dhcp/dhcpv4"
	"github.com/u-root/uio/uio"
	"golang.org/x/net/ipv4"
)

type leaseTime uint32

func (lT leaseTime) String() string {
	return fmt.Sprintf("%d", lT)
}

func (lT leaseTime) ToBytes() []byte {
	time := (uint32)(lT)
	return []byte{(byte)(time >> 24), (byte)((time & 0x00FF0000) >> 16), (byte)((time & 0x0000FF00) >> 8), (byte)(time & 0x000000FF)}
}

type StateCode uint8

const (
	CodeNone         StateCode = iota
	CodeRecvDiscover StateCode = iota
	CodeSentOffer    StateCode = iota
	CodeRecvRequest  StateCode = iota
	CodeSentAck      StateCode = iota
	CodeRecvRelease  StateCode = iota
	CodeReleased     StateCode = iota
)

type ClientInfo struct {
	IP                   net.IP
	State                StateCode
	SessionEstablished   bool
	ValidForcerenewNonce bool
	ForcerenewNonce      [16]byte
	TransactionID        [4]byte
}

type Clients struct {
	Value map[[6]byte]ClientInfo
	Mutex sync.RWMutex
}

type dhcpIP []byte

func (dIP dhcpIP) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", dIP[0], dIP[1], dIP[2], dIP[3])
}

func (dIP dhcpIP) ToBytes() []byte {
	return []byte(dIP)
}

var ServerIP dhcpIP

var addressLeaseTime int = 60 // TODO: Cambiar esto a un valor más razonable (en segundos)

func NewOfferFromDiscover(discover *dhcpv4.DHCPv4, clients *Clients) (*dhcpv4.DHCPv4, error) {

	macAddr := ([6]byte)(discover.ClientHWAddr)

	clients.Mutex.RLock()
	client, ok := clients.Value[macAddr]
	clients.Mutex.RUnlock()

	// Discover is ignored if there is an ongoing request
	if ok && (client.State == CodeRecvDiscover || client.State == CodeRecvRequest ||
		client.State == CodeRecvRelease) {
		return nil, fmt.Errorf("ongoing request for this client")
	}

	if !ok {
		client = ClientInfo{ // TODO: Add 5G here (https://github.com/Rotchamar/STGUTG/blob/feature/agf-dhcp/src/stgutg/dhcp.go)
			IP:                 net.IPv4(10, 2, 0, 100), // nil
			State:              CodeRecvDiscover,
			SessionEstablished: false,
		}
		// TODO: Probando el forcerenew
		go func() {
			time.Sleep(15 * time.Second)
			SendForceRenew(macAddr, clients)
		}()
	} else {
		client.State = CodeRecvDiscover
	}

	client.ValidForcerenewNonce = false // Required for resetting the Nonce for new connections
	client.TransactionID = discover.TransactionID

	// The state is set so that no other discover is processed
	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	// If !ok 						-> register, establish session and establish DHCP
	// If ok && !SessionEstablished -> establish session and establish DHCP
	// If ok && SessionEstablished	-> establish DHCP

	// TODO: Add 5G here (https://github.com/Rotchamar/STGUTG/blob/feature/agf-dhcp/src/stgutg/dhcp.go) (ejemplo antiguo)

	// Establish DCHP

	offer, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	offer.OpCode = dhcpv4.OpcodeBootReply
	offer.TransactionID = client.TransactionID
	offer.ServerIPAddr = net.IP(ServerIP)
	offer.Flags = discover.Flags
	offer.GatewayIPAddr = discover.GatewayIPAddr
	offer.ClientHWAddr = discover.ClientHWAddr

	offer.YourIPAddr = client.IP

	offer.ServerHostName = "AGF\x00"

	offer.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeOffer},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
		dhcpv4.Option{Code: dhcpv4.OptionIPAddressLeaseTime, Value: leaseTime(addressLeaseTime)},
		dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpIP([]byte{0xff, 0xff, 0xff, 0x00})},
		dhcpv4.Option{Code: dhcpv4.OptionClasslessStaticRoute, Value: dhcpIP(append([]byte{0x00}, ServerIP.ToBytes()...))},
		dhcpv4.Option{Code: dhcpv4.OptionForcerenewNonceCapable, Value: dhcpv4.AlgorithmHMAC_MD5},
	)

	client.State = CodeSentOffer

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	return offer, nil

}

func NewAckFromRequest(request *dhcpv4.DHCPv4, clients *Clients) (*dhcpv4.DHCPv4, error) {

	macAddr := ([6]byte)(request.ClientHWAddr)

	clients.Mutex.RLock()
	client, ok := clients.Value[macAddr]
	clients.Mutex.RUnlock()

	// Request is ignored if there is an ongoing request
	if ok && (client.State == CodeRecvDiscover || client.State == CodeRecvRequest ||
		client.State == CodeRecvRelease) {
		return nil, fmt.Errorf("ongoing discover/request")
	}

	// A NAK message is generated if there isn't an existing established session
	if !ok { // !ok || (ok && !client.SessionEstablished)
		return generateNAK(macAddr, request.TransactionID)
	}

	// The state is modified so that no other discover is processed
	client.State = CodeRecvRequest // TODO: dependiendo de la situación, esto puede llegar a cascar si varias requests llegan a la vez (creo)
	// se puede solucionar metiendo todo este bloque dentro del mutex, pero toca ver el impacto en el rendimiento

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	ack, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	ack.OpCode = dhcpv4.OpcodeBootReply
	ack.TransactionID = client.TransactionID
	ack.ServerIPAddr = net.IP(ServerIP)
	ack.Flags = request.Flags
	ack.GatewayIPAddr = request.GatewayIPAddr
	ack.ClientHWAddr = request.ClientHWAddr

	ack.YourIPAddr = client.IP

	ack.ServerHostName = "AGF\x00"

	ack.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeAck},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
		dhcpv4.Option{Code: dhcpv4.OptionIPAddressLeaseTime, Value: leaseTime(addressLeaseTime)},
		dhcpv4.Option{Code: dhcpv4.OptionSubnetMask, Value: dhcpIP([]byte{0xff, 0xff, 0xff, 0x00})},
		dhcpv4.Option{Code: dhcpv4.OptionClasslessStaticRoute, Value: dhcpIP(append([]byte{0x00}, ServerIP.ToBytes()...))}, // TODO: Cambiar el default gateway cuando sea necesario
	)

	// Generate and add Nonce value to options if there is no valid nonce stored
	if !client.ValidForcerenewNonce {
		_, err = rand.Read(client.ForcerenewNonce[:])
		if err != nil {
			return nil, err
		}

		ack.Options.Update(dhcpv4.Option{
			Code: dhcpv4.OptionAuthentication,
			Value: AuthenticationOption{
				Protocol:        3, // (Reconfigure Key) per [RFC3118]
				Algorithm:       dhcpv4.AlgorithmHMAC_MD5,
				RDM:             0,                             // 0x00 as per [RFC3315]
				ReplayDetection: uint64(time.Now().UnixNano()), // Monotonically increasing counter as per RDM = 0x00
				AuthInfo: AuthenticationInformation{
					Type:  1, // Forcerenew nonce Value
					Value: [16]uint8(client.ForcerenewNonce),
				},
			}})

		client.ValidForcerenewNonce = true
	}

	client.State = CodeSentAck

	clients.Mutex.Lock()
	clients.Value[macAddr] = client
	clients.Mutex.Unlock()

	return ack, nil

}

func ReleaseClient(release *dhcpv4.DHCPv4, clients *Clients) { // TODO: quitarlo tambien del AGF y del core
	macAddr := ([6]byte)(release.ClientHWAddr)

	clients.Mutex.RLock()
	delete(clients.Value, macAddr)
	clients.Mutex.RUnlock()
}

func generateNAK(mac [6]byte, xid dhcpv4.TransactionID) (*dhcpv4.DHCPv4, error) {

	nak, err := dhcpv4.New()
	if err != nil {
		return nil, err
	}

	nak.OpCode = dhcpv4.OpcodeBootReply
	nak.TransactionID = xid
	nak.ClientHWAddr = net.HardwareAddr(mac[:])

	nak.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeNak},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
	)

	return nak, nil
}

func sendEthFromDHCP(dhcp_msg *dhcpv4.DHCPv4, ethSocketConn EthSocketConn) {
	dhcp_msg_b := dhcp_msg.ToBytes()

	udp_hdr_b := make([]byte, 8+len(dhcp_msg_b))

	copy(udp_hdr_b[0:], []byte{0x00, 0x43, 0x00, 0x44})                                     // src and dst udp ports
	copy(udp_hdr_b[4:], []byte{uint8(len(udp_hdr_b) >> 8), uint8(len(udp_hdr_b) & 0x00ff)}) // udp + payload length
	copy(udp_hdr_b[6:], []byte{0x00, 0x00})                                                 // null checksum
	copy(udp_hdr_b[8:], dhcp_msg_b)                                                         // payload

	ip_hdr := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(udp_hdr_b),
		TTL:      64,
		Protocol: 17,
		Src:      dhcp_msg.Options[dhcpv4.OptionServerIdentifier.Code()],
		Dst:      dhcp_msg.YourIPAddr,
	}

	// fmt.Println(ip_hdr)

	ip_hdr_b, err := ip_hdr.Marshal()
	if err != nil {
		log.Print(err)
		return
	}

	var checksum_value_32 uint32 = 0
	for i := 0; i < len(ip_hdr_b); i += 2 {
		checksum_value_32 += (uint32)(ip_hdr_b[i])<<8 + (uint32)(ip_hdr_b[i+1])
	}
	checksum_value_16 := ^(uint16)(checksum_value_32&0xFFFF + checksum_value_32>>16)
	checksum_b := []byte{(byte)(checksum_value_16 >> 8), (byte)(checksum_value_16 & 0xFF)}

	copy(ip_hdr_b[10:], checksum_b)

	ip_hdr_b = append(ip_hdr_b, udp_hdr_b...)

	eth_frame_b := make([]byte, len(ip_hdr_b)+14)

	copy(eth_frame_b[0:], dhcp_msg.ClientHWAddr)
	copy(eth_frame_b[6:], ethSocketConn.Iface.HardwareAddr)
	copy(eth_frame_b[12:], []byte{0x08, 0x00}) // Type: IPv4
	copy(eth_frame_b[14:], ip_hdr_b)

	err = syscall.Sendto(ethSocketConn.Fd, eth_frame_b, 0, &(ethSocketConn.Addr))
	if err != nil {
		log.Print(err)
		return
	}

}

type EthSocketConn struct {
	Iface *net.Interface
	Addr  syscall.SockaddrLinklayer
	Fd    int
}

func NewEthSocketConn(ifname string) (EthSocketConn, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return EthSocketConn{}, fmt.Errorf("get link by name: %s", err)
	}

	addr := syscall.SockaddrLinklayer{
		Ifindex: iface.Index,
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300) // 0x0300 = syscall.ETH_P_ALL
	if err != nil {
		return EthSocketConn{}, fmt.Errorf("create Ethernet raw socket: %s", err)
	}
	err = syscall.Bind(fd, &addr)
	if err != nil {
		return EthSocketConn{}, fmt.Errorf("bind Ethernet raw socket: %s", err)
	}

	socketConn := EthSocketConn{
		Iface: iface,
		Addr:  addr,
		Fd:    fd,
	}

	return socketConn, nil
}

type AuthenticationOption struct {
	// Code            uint8
	// Length          uint8
	Protocol        uint8
	Algorithm       dhcpv4.AlgorithmType
	RDM             uint8
	ReplayDetection uint64
	AuthInfo        AuthenticationInformation
}

type AuthenticationInformation struct {
	Type  uint8
	Value [16]byte
}

func (a AuthenticationOption) ToBytes() []byte {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.BigEndian, a)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func (a AuthenticationOption) String() string {
	switch a.AuthInfo.Type {
	case 1:
		return fmt.Sprintf("Forcerenew Nonce Value: %x\n", a.AuthInfo.Value)
	case 2:
		return fmt.Sprintf("HMAC-MD5 digest: %x\n", a.AuthInfo.Value)
	default:
		return fmt.Sprintf("Unknown Authentication Information Type value: %d", a.AuthInfo.Type)
	}
}

func FromBytes(q []byte) AuthenticationOption {
	var a AuthenticationOption
	buf := uio.NewBigEndianBuffer(q)

	a.Protocol = buf.Read8()
	a.Algorithm = dhcpv4.AlgorithmType(buf.Read8())
	a.RDM = buf.Read8()
	a.ReplayDetection = buf.Read64()
	a.AuthInfo.Type = buf.Read8()
	a.AuthInfo.Value = [16]byte(buf.CopyN(16))

	return a
}

func SendForceRenew(clientHWAddr [6]byte, clients *Clients) error {

	clients.Mutex.RLock()
	client, ok := clients.Value[clientHWAddr]
	clients.Mutex.RUnlock()
	if !ok {
		return fmt.Errorf("could not find client with HWAddr = %x", clientHWAddr)
	}

	forcerenew, err := dhcpv4.New()
	if err != nil {
		return err
	}

	forcerenew.OpCode = dhcpv4.OpcodeBootReply
	forcerenew.TransactionID = client.TransactionID
	forcerenew.YourIPAddr = client.IP
	forcerenew.ServerIPAddr = net.IP(ServerIP)
	forcerenew.ClientHWAddr = clientHWAddr[:]
	forcerenew.ServerHostName = "AGF\x00"

	replayDetection := uint64(time.Now().UnixNano())

	forcerenew.Options = dhcpv4.OptionsFromList(
		dhcpv4.Option{Code: dhcpv4.OptionDHCPMessageType, Value: dhcpv4.MessageTypeForceRenew},
		dhcpv4.Option{Code: dhcpv4.OptionServerIdentifier, Value: ServerIP},
		dhcpv4.Option{
			Code: dhcpv4.OptionAuthentication,
			Value: AuthenticationOption{
				Protocol:        3, // RFC6704: (Reconfigure Key) per [RFC3118]
				Algorithm:       dhcpv4.AlgorithmHMAC_MD5,
				RDM:             0,               // 0x00 as per [RFC3315]
				ReplayDetection: replayDetection, // Monotonically increasing counter as per RDM = 0x00
				AuthInfo: AuthenticationInformation{
					Type: 2, // HMAC-MD5 digest of the message
					// Value left empty for hmac calculation
				},
			}})

	hmacmd5 := hmac.New(md5.New, client.ForcerenewNonce[:])
	_, err = hmacmd5.Write(forcerenew.ToBytes())
	if err != nil {
		return err
	}
	digest := hmacmd5.Sum(nil)

	forcerenew.UpdateOption(dhcpv4.Option{
		Code: dhcpv4.OptionAuthentication,
		Value: AuthenticationOption{
			Protocol:        3, // (Reconfigure Key) per [RFC3118]
			Algorithm:       dhcpv4.AlgorithmHMAC_MD5,
			RDM:             0,               // 0x00 as per [RFC3315]
			ReplayDetection: replayDetection, // Monotonically increasing counter as per RDM = 0x00
			AuthInfo: AuthenticationInformation{
				Type:  2, // HMAC-MD5 digest of the message
				Value: [16]byte(digest),
			},
		}})

	sendEthFromDHCP(forcerenew, EthConn) // TODO: Should retransmit if no response is received

	return nil
}

// https://gist.github.com/schwarzeni/f25031a3123f895ff3785970921e962c
func GetInterfaceIpv4Addr(interfaceName string) ([]byte, error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
		err      error
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return nil, err
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return nil, err
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return nil, fmt.Errorf("interface %s don't have an ipv4 address", interfaceName)
	}
	return ipv4Addr, nil
}
