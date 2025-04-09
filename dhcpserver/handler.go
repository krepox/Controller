package dhcpserver

import (
	"bytes"
	"log"
	"net"

	"github.com/Rotchamar/dhcp/dhcpv4"
)

// handlerDHCP procesa los mensajes DHCP DISCOVER, REQUEST y RELEASE
func handlerDHCP(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	log.Print(m.Summary())

	switch m.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		if !bytes.Equal(m.Options[dhcpv4.OptionForcerenewNonceCapable.Code()], dhcpv4.AlgorithmHMAC_MD5.ToBytes()) {
			return // Ignorar si no es ForceRenew Capable
		}
		offer, err := NewOfferFromDiscover(m, &DHCPClients)
		if err != nil {
			return
		}
		sendEthFromDHCP(offer, EthConn)

	case dhcpv4.MessageTypeRequest:
		if !bytes.Equal(m.Options[dhcpv4.OptionForcerenewNonceCapable.Code()], dhcpv4.AlgorithmHMAC_MD5.ToBytes()) {
			return // Ignorar si no es ForceRenew Capable
		}
		ack, err := NewAckFromRequest(m, &DHCPClients)
		if err != nil {
			return
		}
		sendEthFromDHCP(ack, EthConn)

	case dhcpv4.MessageTypeRelease:
		ReleaseClient(m, &DHCPClients)
	}
}
