package dhcpserver

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Rotchamar/dhcp/dhcpv4"
	"github.com/Rotchamar/dhcp/dhcpv4/server4"
)

var DHCPClients Clients
var EthConn EthSocketConn

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

	log.Println(" DHCP Server corriendo en UDP :67")
	server.Serve()
}

func TriggerDHCPClient(ueIP string) error {
	url := fmt.Sprintf("http://%s:8081/dhcp/start", ueIP)
	log.Printf("➡️  Lanzando GET a %s", url)

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("fallo al llamar a %s: %w", url, err)
	}
	defer resp.Body.Close()

	log.Printf(" Respuesta desde %s: %s", ueIP, resp.Status)
	return nil
}
