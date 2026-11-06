package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"

	"esp-wrap/pkg/esp"
)

type Config struct {
	ListenAddr string        `json:"listen_addr"`
	TunName    string        `json:"tun_name"`
	TunIP      string        `json:"tun_ip"`
	TunCIDR    int           `json:"tun_cidr"`
	TunMTU     int           `json:"tun_mtu"`
	DisableTun bool          `json:"disable_tun,omitempty"`
	Key        string        `json:"key,omitempty"`
	PrivateKey string        `json:"private_key,omitempty"`
	PublicKey  string        `json:"public_key,omitempty"`
	Clients    []ClientEntry `json:"clients"`
}

type ClientEntry struct {
	Name string `json:"name"`
	UUID string `json:"uuid,omitempty"`
}

type ClientSession struct {
	Name        string
	UUID        string
	UUIDBytes   [16]byte
	SPI         uint32
	CurrentIP   atomic.Pointer[net.IP]
	CurrentIP32 atomic.Uint32
	CipherMu    sync.RWMutex
	Cipher      *esp.Cipher
	AntiReplay  *esp.AntiReplay
	RemoteAddr  atomic.Pointer[net.IPAddr]
	Seq         atomic.Uint32
	LastSeen    atomic.Int64
}

type IPPool16 struct {
	mu        sync.Mutex
	baseNet   uint32
	allocated map[uint32]*ClientSession
}

func NewIPPool16(serverIP net.IP) *IPPool16 {
	ip4 := serverIP.To4()
	base := binary.BigEndian.Uint32(ip4) & 0xFFFF0000
	return &IPPool16{
		baseNet:   base,
		allocated: make(map[uint32]*ClientSession),
	}
}

func (p *IPPool16) AllocateRandom(session *ClientSession) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for k, v := range p.allocated {
		if v == session {
			delete(p.allocated, k)
			break
		}
	}

	start, _ := rand.Int(rand.Reader, big.NewInt(65530))
	offset := uint32(start.Int64() + 2)

	for i := uint32(0); i < 65530; i++ {
		candidateOffset := ((offset - 2 + i) % 65530) + 2
		lastByte := candidateOffset & 0xFF
		if lastByte == 0 || lastByte == 255 {
			continue
		}
		candidateIPNum := p.baseNet | candidateOffset
		if _, ok := p.allocated[candidateIPNum]; !ok {
			p.allocated[candidateIPNum] = session
			res := make(net.IP, 4)
			binary.BigEndian.PutUint32(res, candidateIPNum)
			return res, nil
		}
	}

	return nil, errors.New("ip pool /16 exhausted")
}

func (p *IPPool16) Release(session *ClientSession) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.allocated {
		if v == session {
			delete(p.allocated, k)
			break
		}
	}
}

func calculateSubnet(tunIP string, tunCIDR int) string {
	ip := net.ParseIP(tunIP).To4()
	if ip == nil {
		return ""
	}
	mask := net.CIDRMask(tunCIDR, 32)
	subnetIP := ip.Mask(mask)
	return fmt.Sprintf("%s/%d", subnetIP.String(), tunCIDR)
}

func configureFirewall(tunIP string, tunCIDR int) {
	exec.Command("iptables", "-C", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-I", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()

	exec.Command("iptables", "-C", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()
	exec.Command("iptables", "-I", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()

	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	subnet := calculateSubnet(tunIP, tunCIDR)
	if subnet != "" {
		if err := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run(); err != nil {
			exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run()
		}

		exec.Command("iptables", "-D", "FORWARD", "-s", subnet, "-d", subnet, "-j", "DROP").Run()
		exec.Command("iptables", "-I", "FORWARD", "1", "-s", subnet, "-d", subnet, "-j", "DROP").Run()

		exec.Command("iptables", "-I", "FORWARD", "2", "-s", subnet, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-I", "FORWARD", "3", "-d", subnet, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	}
}

func cleanupFirewall(tunIP string, tunCIDR int) {
	exec.Command("iptables", "-D", "INPUT", "-p", "esp", "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "OUTPUT", "-p", "icmp", "--icmp-type", "3/2", "-j", "DROP").Run()

	subnet := calculateSubnet(tunIP, tunCIDR)
	if subnet != "" {
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-d", subnet, "-j", "MASQUERADE").Run()
		exec.Command("iptables", "-D", "FORWARD", "-s", subnet, "-d", subnet, "-j", "DROP").Run()
		exec.Command("iptables", "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-D", "FORWARD", "-d", subnet, "-j", "ACCEPT").Run()
		exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	}
}

func handleGenKey() {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	fmt.Printf("PrivateKey: %s\n", privB64)
	fmt.Printf("PublicKey:  %s\n", pubB64)
}

func handleAddUser(configPath, username string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", configPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse %s: %v", configPath, err)
	}

	for _, c := range cfg.Clients {
		if c.Name == username {
			log.Fatalf("user %s already exists", username)
		}
	}

	curve := ecdh.X25519()
	var serverPriv *ecdh.PrivateKey
	if cfg.PrivateKey != "" {
		dec, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err == nil && len(dec) == 32 {
			serverPriv, _ = curve.NewPrivateKey(dec)
		}
	}
	if serverPriv == nil {
		serverPriv, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate server private key: %v", err)
		}
		cfg.PrivateKey = base64.StdEncoding.EncodeToString(serverPriv.Bytes())
	}
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())
	cfg.PublicKey = serverPubB64

	userUUID := esp.GenerateUUID()
	cfg.Clients = append(cfg.Clients, ClientEntry{
		Name: username,
		UUID: userUUID,
	})

	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, updated, 0600); err != nil {
		log.Fatalf("failed to write %s: %v", configPath, err)
	}

	serverHost := cfg.ListenAddr
	if serverHost == "0.0.0.0" || serverHost == "" {
		out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
		if err == nil {
			fields := strings.Fields(string(out))
			for i, f := range fields {
				if f == "src" && i+1 < len(fields) {
					serverHost = fields[i+1]
					break
				}
			}
		}
	}

	clientConfigMap := map[string]interface{}{
		"server_addr":       serverHost,
		"server_public_key": serverPubB64,
		"uuid":              userUUID,
		"socks_listen":      "127.0.0.1:10951",
	}

	clientJSON, _ := json.MarshalIndent(clientConfigMap, "", "  ")
	configDir := filepath.Dir(configPath)
	clientFileName := filepath.Join(configDir, fmt.Sprintf("client_%s.json", username))
	_ = os.WriteFile(clientFileName, clientJSON, 0600)

	fmt.Printf("[+] User %s added successfully!\n", username)
	fmt.Printf("    UUID:              %s\n", userUUID)
	fmt.Printf("    Server PublicKey:  %s\n", serverPubB64)
	fmt.Printf("    Saved config:      %s\n", clientFileName)
}

func handleListUsers(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", configPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse %s: %v", configPath, err)
	}

	curve := ecdh.X25519()
	var serverPubBytes []byte
	if cfg.PublicKey != "" {
		serverPubBytes, _ = base64.StdEncoding.DecodeString(cfg.PublicKey)
	} else if cfg.PrivateKey != "" {
		dec, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err == nil && len(dec) == 32 {
			priv, err := curve.NewPrivateKey(dec)
			if err == nil {
				serverPubBytes = priv.PublicKey().Bytes()
			}
		}
	}

	fmt.Printf("%-15s %-40s %-12s\n", "NAME", "UUID", "SPI")
	fmt.Println(strings.Repeat("-", 70))
	for _, c := range cfg.Clients {
		name := c.Name
		if name == "" {
			name = "unnamed"
		}
		u := c.UUID
		spiStr := "-"
		if u != "" && len(serverPubBytes) == 32 {
			if b, err := esp.ParseUUID(u); err == nil {
				spiStr = fmt.Sprintf("0x%08x", esp.DeriveRealitySPI(b[:], serverPubBytes))
			}
		}
		fmt.Printf("%-15s %-40s %-12s\n", name, u, spiStr)
	}
}

func handleDelUser(configPath, username string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("failed to read %s: %v", configPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse %s: %v", configPath, err)
	}

	var newClients []ClientEntry
	found := false
	for _, c := range cfg.Clients {
		if c.Name == username {
			found = true
			continue
		}
		newClients = append(newClients, c)
	}
	if !found {
		log.Fatalf("user %s not found", username)
	}

	cfg.Clients = newClients
	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, updated, 0600); err != nil {
		log.Fatalf("failed to write %s: %v", configPath, err)
	}
	fmt.Printf("[+] User %s deleted successfully.\n", username)
}

func main() {
	configPath := flag.String("c", "server.json", "path to server.json")
	genKey := flag.Bool("gen-key", false, "generate server private key and exit")
	genUUID := flag.Bool("gen-uuid", false, "generate random client UUID and exit")
	noTun := flag.Bool("no-tun", false, "disable TUN interface creation and routing")
	addUser := flag.String("add-user", "", "add new user to server.json and generate client config")
	listUsers := flag.Bool("list-users", false, "list all registered users")
	delUser := flag.String("del-user", "", "delete user from server.json")
	flag.Parse()

	if *genKey {
		handleGenKey()
		return
	}
	if *genUUID {
		fmt.Printf("UUID: %s\n", esp.GenerateUUID())
		return
	}
	if *addUser != "" {
		handleAddUser(*configPath, *addUser)
		return
	}
	if *listUsers {
		handleListUsers(*configPath)
		return
	}
	if *delUser != "" {
		handleDelUser(*configPath, *delUser)
		return
	}

	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("failed to read config: %v", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("failed to parse config: %v", err)
	}

	if *noTun {
		cfg.DisableTun = true
	}

	if cfg.TunName == "" {
		cfg.TunName = "tun-esp0"
	}
	if cfg.TunMTU <= 0 {
		cfg.TunMTU = 1360
	}
	if cfg.TunCIDR <= 0 {
		cfg.TunCIDR = 16
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0"
	}

	curve := ecdh.X25519()
	var serverPriv *ecdh.PrivateKey

	if cfg.PrivateKey != "" {
		dec, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
		if err == nil && len(dec) == 32 {
			serverPriv, _ = curve.NewPrivateKey(dec)
		}
	}
	if serverPriv == nil {
		serverPriv, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate server private key: %v", err)
		}
		cfg.PrivateKey = base64.StdEncoding.EncodeToString(serverPriv.Bytes())
		cfg.PublicKey = base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())
		updated, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(*configPath, updated, 0600)
	}

	serverPub := serverPriv.PublicKey()
	serverPubBytes := serverPub.Bytes()
	serverPubB64 := base64.StdEncoding.EncodeToString(serverPubBytes)
	if cfg.PublicKey != serverPubB64 {
		cfg.PublicKey = serverPubB64
		updated, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(*configPath, updated, 0600)
	}

	clientsBySPI := make(map[uint32]*ClientSession)
	var clientsByTunIPMu sync.RWMutex
	clientsByTunIP := make(map[uint32]*ClientSession)

	serverTunIP := net.ParseIP(cfg.TunIP)
	if serverTunIP == nil {
		log.Fatalf("invalid server tun_ip: %s", cfg.TunIP)
	}
	ipPool := NewIPPool16(serverTunIP)

	for _, ce := range cfg.Clients {
		if ce.UUID == "" {
			continue
		}
		ub, err := esp.ParseUUID(ce.UUID)
		if err != nil {
			log.Fatalf("invalid uuid for client %s: %v", ce.Name, err)
		}
		spiVal := esp.DeriveRealitySPI(ub[:], serverPubBytes)

		session := &ClientSession{
			Name:       ce.Name,
			UUID:       ce.UUID,
			UUIDBytes:  ub,
			SPI:        spiVal,
			AntiReplay: esp.NewAntiReplay(),
		}

		clientsBySPI[spiVal] = session
	}

	_, clientSubnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", cfg.TunIP, cfg.TunCIDR))
	if err != nil {
		log.Fatalf("invalid subnet cidr: %v", err)
	}

	var tun *water.Interface
	cidrStr := fmt.Sprintf("%s/%d", cfg.TunIP, cfg.TunCIDR)
	if !cfg.DisableTun {
		var err error
		tun, err = water.New(water.Config{
			DeviceType: water.TUN,
			PlatformSpecificParams: water.PlatformSpecificParams{
				Name: cfg.TunName,
			},
		})
		if err != nil {
			exec.Command("ip", "link", "del", cfg.TunName).Run()
			tun, err = water.New(water.Config{
				DeviceType: water.TUN,
				PlatformSpecificParams: water.PlatformSpecificParams{
					Name: cfg.TunName,
				},
			})
			if err != nil {
				log.Fatalf("failed to create tun device %s: %v", cfg.TunName, err)
			}
		}
		defer tun.Close()

		if out, err := exec.Command("ip", "addr", "replace", cidrStr, "dev", cfg.TunName).CombinedOutput(); err != nil {
			log.Fatalf("failed to assign ip to tun: %v, out: %s", err, string(out))
		}
		if out, err := exec.Command("ip", "link", "set", "dev", cfg.TunName, "mtu", strconv.Itoa(cfg.TunMTU), "up").CombinedOutput(); err != nil {
			log.Fatalf("failed to bring tun up: %v, out: %s", err, string(out))
		}

		exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", cfg.TunName)).Run()
		configureFirewall(cfg.TunIP, cfg.TunCIDR)
		defer cleanupFirewall(cfg.TunIP, cfg.TunCIDR)
	}

	rawConn, err := net.ListenPacket("ip4:50", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("failed to open raw esp socket: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Printf("shutting down server...")
		cancel()
		rawConn.Close()
		if tun != nil {
			tun.Close()
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().Unix()
				for _, session := range clientsBySPI {
					last := session.LastSeen.Load()
					if last > 0 && now-last > 600 {
						currIP := session.CurrentIP.Load()
						if currIP != nil {
							ipU32 := session.CurrentIP32.Swap(0)
							session.CurrentIP.Store(nil)
							session.CipherMu.Lock()
							session.Cipher = nil
							session.CipherMu.Unlock()
							ipPool.Release(session)
							clientsByTunIPMu.Lock()
							if ipU32 != 0 {
								delete(clientsByTunIP, ipU32)
							}
							clientsByTunIPMu.Unlock()
							log.Printf("session %s (0x%08x) expired after 10m idle, released IP %s", session.Name, session.SPI, *currIP)
						}
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, from, err := rawConn.ReadFrom(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}

			if n < esp.MinPacketSize {
				continue
			}

			packet := esp.StripIPv4Header(buf[:n])
			if len(packet) < esp.MinPacketSize {
				continue
			}

			spi, err := esp.PeekSPI(packet)
			if err != nil {
				continue
			}

			session, ok := clientsBySPI[spi]
			if !ok {
				continue
			}

			bootTime, seq, err := esp.ExtractBootTimeAndSeq(packet)
			if err != nil {
				continue
			}

			var ciph *esp.Cipher
			session.CipherMu.RLock()
			ciph = session.Cipher
			session.CipherMu.RUnlock()

			var nextHdr uint8
			var inner []byte

			if ciph != nil && session.AntiReplay.Check(bootTime, seq) {
				nextHdr, inner, err = ciph.Unpack(packet)
				if err == nil {
					session.AntiReplay.Update(bootTime, seq)
				}
			}

			if inner == nil {
				newCiph, req, err := esp.UnpackHandshakeReq(packet, serverPriv, session.UUIDBytes)
				if err == nil {
					if session.AntiReplay.Check(bootTime, seq) {
						session.AntiReplay.Update(bootTime, seq)
					}
					session.CipherMu.Lock()
					session.Cipher = newCiph
					session.CipherMu.Unlock()
					ciph = newCiph

					allocatedIP, err := ipPool.AllocateRandom(session)
					if err == nil {
						ipU32 := binary.BigEndian.Uint32(allocatedIP.To4())
						oldIPU32 := session.CurrentIP32.Swap(ipU32)
						session.CurrentIP.Store(&allocatedIP)

						clientsByTunIPMu.Lock()
						if oldIPU32 != 0 && oldIPU32 != ipU32 {
							delete(clientsByTunIP, oldIPU32)
						}
						clientsByTunIP[ipU32] = session
						clientsByTunIPMu.Unlock()
						log.Printf("client 0x%08x (%s) allocated dynamic random IP: %s (req bootTime: %d)", session.SPI, session.Name, allocatedIP, req.BootTime)
					}

					if ipAddr, ok := from.(*net.IPAddr); ok {
						session.RemoteAddr.Store(ipAddr)
					}
					session.LastSeen.Store(time.Now().Unix())

					currIP := session.CurrentIP.Load()
					if currIP != nil {
						respBytes := esp.EncodeHandshakeResp(*currIP, serverTunIP, cfg.TunCIDR, cfg.TunMTU, net.ParseIP("8.8.8.8"))
						respSeq := session.Seq.Add(1)
						packedResp, err := ciph.Pack(session.SPI, respSeq, esp.ProtoControl, respBytes)
						if err == nil {
							targetAddr := session.RemoteAddr.Load()
							if targetAddr != nil {
								rawConn.WriteTo(packedResp, targetAddr)
							}
						}
					}
					continue
				}
				continue
			}

			session.LastSeen.Store(time.Now().Unix())

			if ipAddr, ok := from.(*net.IPAddr); ok {
				current := session.RemoteAddr.Load()
				if current == nil || !current.IP.Equal(ipAddr.IP) {
					session.RemoteAddr.Store(ipAddr)
				}
			}

			if nextHdr == esp.ProtoControl {
				if len(inner) > 0 && inner[0] == esp.ControlKeepalive {
					ackSeq := session.Seq.Add(1)
					packedAck, err := ciph.Pack(session.SPI, ackSeq, esp.ProtoControl, []byte{esp.ControlKeepalive})
					if err == nil {
						targetAddr := session.RemoteAddr.Load()
						if targetAddr != nil {
							rawConn.WriteTo(packedAck, targetAddr)
						}
					}
				}
				continue
			}

			if nextHdr == esp.ProtoIPv4 && len(inner) >= 20 {
				currIP := session.CurrentIP.Load()
				if currIP == nil {
					continue
				}

				srcIP := net.IP(inner[12:16])
				if !srcIP.Equal(*currIP) {
					continue
				}

				dstIP := net.IP(inner[16:20])
				if clientSubnet.Contains(dstIP) && !dstIP.Equal(serverTunIP) {
					continue
				}

				if tun != nil {
					if _, err := tun.Write(inner); err != nil {
						select {
						case <-ctx.Done():
							return
						default:
						}
					}
				}
			}
		}
	}()

	if tun != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 65535)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				n, err := tun.Read(buf)
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}

				if n < 20 || (buf[0]>>4) != 4 {
					continue
				}

				srcIP := net.IP(buf[12:16])
				if clientSubnet.Contains(srcIP) && !srcIP.Equal(serverTunIP) {
					continue
				}

				dstIPNum := binary.BigEndian.Uint32(buf[16:20])

				clientsByTunIPMu.RLock()
				session, ok := clientsByTunIP[dstIPNum]
				clientsByTunIPMu.RUnlock()

				if !ok {
					continue
				}

				targetAddr := session.RemoteAddr.Load()
				if targetAddr == nil {
					continue
				}

				session.CipherMu.RLock()
				ciph := session.Cipher
				session.CipherMu.RUnlock()

				if ciph == nil {
					continue
				}

				seq := session.Seq.Add(1)
				packed, err := ciph.Pack(session.SPI, seq, esp.ProtoIPv4, buf[:n])
				if err != nil {
					continue
				}

				if _, err := rawConn.WriteTo(packed, targetAddr); err != nil {
					select {
					case <-ctx.Done():
						return
					default:
					}
				}
			}
		}()
	}

	if cfg.DisableTun {
		log.Printf("esp-server running. Listening: %s (Proto 50), TUN: disabled (no-tun mode), Reality ECDH active", cfg.ListenAddr)
	} else {
		log.Printf("esp-server running. Listening: %s (Proto 50), Tun: %s (%s), Reality ECDH + /16 Dynamic Random Pool active", cfg.ListenAddr, cfg.TunName, cidrStr)
	}
	wg.Wait()
	log.Printf("esp-server exited cleanly")
}
