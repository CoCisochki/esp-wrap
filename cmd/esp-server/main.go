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
	PrivateKey string        `json:"private_key"`
	PublicKey  string        `json:"public_key"`
	Clients    []ClientEntry `json:"clients"`
}

type ClientEntry struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type ClientSession struct {
	Name                    string
	UUID                    string
	UUIDBytes               [16]byte
	AuthSPI                 uint32
	Mac1Key                 [32]byte
	LastClientHandshakeNano int64
	LastArrivalServerNano   int64
	RateLimitMu             sync.Mutex

	SessionSPIMu   sync.RWMutex
	SessionSPI     uint32
	Cipher         *esp.SessionCipher
	AntiReplay     *esp.AntiReplay

	PrevSessionSPI uint32
	PrevCipher     *esp.SessionCipher
	PrevAntiReplay *esp.AntiReplay
	PrevExpiry     time.Time

	CurrentIP   atomic.Pointer[net.IP]
	CurrentIP32 atomic.Uint32
	RemoteAddr  atomic.Pointer[net.Addr]
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

	fmt.Printf("%-15s %-40s %-12s\n", "NAME", "UUID", "AUTH_SPI")
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
				spiStr = fmt.Sprintf("0x%08x", esp.DeriveAuthSPI(serverPubBytes, b))
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
	if cfg.TunIP == "" {
		cfg.TunIP = "10.99.0.1"
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

	clientsByAuthSPI := make(map[uint32]*ClientSession)
	var sessionsBySessionSPIMu sync.RWMutex
	sessionsBySessionSPI := make(map[uint32]*ClientSession)
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
		authSPI := esp.DeriveAuthSPI(serverPubBytes, ub)
		mac1Key := esp.DeriveMac1Key(serverPubBytes, ub)

		session := &ClientSession{
			Name:      ce.Name,
			UUID:      ce.UUID,
			UUIDBytes: ub,
			AuthSPI:   authSPI,
			Mac1Key:   mac1Key,
		}

		clientsByAuthSPI[authSPI] = session
	}

	_, clientSubnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", cfg.TunIP, cfg.TunCIDR))
	if err != nil {
		log.Fatalf("invalid subnet cidr: %v", err)
	}

	var tun *water.Interface
	cidrStr := fmt.Sprintf("%s/%d", cfg.TunIP, cfg.TunCIDR)
	if !cfg.DisableTun {
		var err error
		tun, err = esp.CreateTun(cfg.TunName)
		if err != nil {
			exec.Command("ip", "link", "del", cfg.TunName).Run()
			tun, err = esp.CreateTun(cfg.TunName)
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
				now := time.Now()
				nowUnix := now.Unix()
				sessionsBySessionSPIMu.Lock()
				for sSPI, session := range sessionsBySessionSPI {
					session.SessionSPIMu.Lock()
					if session.PrevSessionSPI != 0 && now.After(session.PrevExpiry) {
						prevSPI := session.PrevSessionSPI
						session.PrevSessionSPI = 0
						session.PrevCipher = nil
						session.PrevAntiReplay = nil
						delete(sessionsBySessionSPI, prevSPI)
					}
					session.SessionSPIMu.Unlock()

					last := session.LastSeen.Load()
					if last > 0 && nowUnix-last > 600 {
						currIP := session.CurrentIP.Load()
						if currIP != nil {
							ipU32 := session.CurrentIP32.Swap(0)
							session.CurrentIP.Store(nil)

							session.SessionSPIMu.Lock()
							activeSPI := session.SessionSPI
							prevSPI := session.PrevSessionSPI
							session.SessionSPI = 0
							session.Cipher = nil
							session.AntiReplay = nil
							session.PrevSessionSPI = 0
							session.PrevCipher = nil
							session.PrevAntiReplay = nil
							session.SessionSPIMu.Unlock()

							if activeSPI != 0 {
								delete(sessionsBySessionSPI, activeSPI)
							}
							if prevSPI != 0 {
								delete(sessionsBySessionSPI, prevSPI)
							}
							ipPool.Release(session)

							clientsByTunIPMu.Lock()
							if ipU32 != 0 {
								delete(clientsByTunIP, ipU32)
							}
							clientsByTunIPMu.Unlock()
							log.Printf("session %s (0x%08x) expired after 10m idle, released IP %s", session.Name, sSPI, *currIP)
						}
					}
				}
				sessionsBySessionSPIMu.Unlock()
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

			if n < 4 {
				continue
			}

			packet := esp.StripIPv4Header(buf[:n])
			if len(packet) < 4 {
				continue
			}

			spi, err := esp.PeekSPI(packet)
			if err != nil {
				continue
			}

			if session, isAuth := clientsByAuthSPI[spi]; isAuth {
				clientEphPubBytes, _, err := esp.UnpackHandshakeReq(packet, session.Mac1Key, &session.LastClientHandshakeNano, &session.LastArrivalServerNano, &session.RateLimitMu)
				if err != nil {
					continue
				}

				clientEphPub, err := curve.NewPublicKey(clientEphPubBytes)
				if err != nil {
					continue
				}

				staticDH, err := serverPriv.ECDH(clientEphPub)
				if err != nil {
					continue
				}

				serverEphPriv, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					continue
				}
				serverEphPubBytes := serverEphPriv.PublicKey().Bytes()

				ephemeralDH, err := serverEphPriv.ECDH(clientEphPub)
				if err != nil {
					continue
				}

				_, serverCipher, err := esp.DeriveSessionCiphers(
					staticDH,
					ephemeralDH,
					serverPubBytes,
					clientEphPubBytes,
					serverEphPubBytes,
					session.UUIDBytes,
				)
				if err != nil {
					continue
				}

				currIP := session.CurrentIP.Load()
				if currIP == nil {
					allocatedIP, err := ipPool.AllocateRandom(session)
					if err != nil {
						log.Printf("ip pool allocation error for %s: %v", session.Name, err)
						continue
					}
					ipU32 := binary.BigEndian.Uint32(allocatedIP.To4())
					session.CurrentIP32.Store(ipU32)
					session.CurrentIP.Store(&allocatedIP)

					clientsByTunIPMu.Lock()
					clientsByTunIP[ipU32] = session
					clientsByTunIPMu.Unlock()
					currIP = &allocatedIP
				}

				var newSessionSPI uint32
				var oldToClean uint32
				sessionsBySessionSPIMu.Lock()
				for {
					s, err := esp.GenerateSessionSPI()
					if err == nil {
						if _, exists := sessionsBySessionSPI[s]; !exists {
							if _, isAuthSPI := clientsByAuthSPI[s]; !isAuthSPI {
								newSessionSPI = s
								break
							}
						}
					}
				}

				session.SessionSPIMu.Lock()
				oldSessionSPI := session.SessionSPI
				oldCipher := session.Cipher
				oldAR := session.AntiReplay

				if oldSessionSPI != 0 && oldCipher != nil && oldAR != nil {
					if session.PrevSessionSPI != 0 && session.PrevSessionSPI != oldSessionSPI {
						oldToClean = session.PrevSessionSPI
					}
					session.PrevSessionSPI = oldSessionSPI
					session.PrevCipher = oldCipher
					session.PrevAntiReplay = oldAR
					session.PrevExpiry = time.Now().Add(30 * time.Second)
				}

				session.SessionSPI = newSessionSPI
				session.Cipher = serverCipher
				session.AntiReplay = esp.NewAntiReplay()
				session.Seq.Store(0)
				session.RemoteAddr.Store(&from)
				session.LastSeen.Store(time.Now().Unix())
				session.SessionSPIMu.Unlock()

				if oldToClean != 0 {
					delete(sessionsBySessionSPI, oldToClean)
				}
				sessionsBySessionSPI[newSessionSPI] = session
				sessionsBySessionSPIMu.Unlock()

				respPayload := &esp.HandshakeRespPayload{
					SessionSPI: newSessionSPI,
					AssignedIP: *currIP,
					GatewayIP:  serverTunIP,
					CIDR:       cfg.TunCIDR,
					MTU:        cfg.TunMTU,
					DNS:        net.ParseIP("8.8.8.8"),
				}

				packedResp, err := esp.PackHandshakeResp(spi, staticDH, clientEphPubBytes, serverEphPubBytes, respPayload)
				if err == nil {
					rawConn.WriteTo(packedResp, from)
					log.Printf("handshake completed for %s from %s. SessionSPI: 0x%08x, Dynamic IP: %s", session.Name, from, newSessionSPI, *currIP)
				}
				continue
			}

			sessionsBySessionSPIMu.RLock()
			session, ok := sessionsBySessionSPI[spi]
			sessionsBySessionSPIMu.RUnlock()

			if !ok || len(packet) < esp.MinPacketSize {
				continue
			}

			seq := binary.BigEndian.Uint32(packet[4:8])

			session.SessionSPIMu.RLock()
			var ciph *esp.SessionCipher
			var ar *esp.AntiReplay
			var matchedSPI uint32
			now := time.Now()

			if spi == session.SessionSPI && session.Cipher != nil {
				ciph = session.Cipher
				ar = session.AntiReplay
				matchedSPI = session.SessionSPI
			} else if spi == session.PrevSessionSPI && session.PrevCipher != nil && now.Before(session.PrevExpiry) {
				ciph = session.PrevCipher
				ar = session.PrevAntiReplay
				matchedSPI = session.PrevSessionSPI
			}
			session.SessionSPIMu.RUnlock()

			if ciph == nil || ar == nil {
				continue
			}

			if !ar.Check(seq) {
				continue
			}

			nextHdr, inner, err := ciph.Unpack(packet)
			if err != nil {
				continue
			}

			ar.Update(seq)
			session.RemoteAddr.Store(&from)
			session.LastSeen.Store(time.Now().Unix())

			if nextHdr == esp.ProtoControl {
				if len(inner) > 0 && inner[0] == esp.ControlKeepalive {
					ackSeq := session.Seq.Add(1)
					packedAck, err := ciph.Pack(matchedSPI, ackSeq, esp.ProtoControl, []byte{esp.ControlKeepalive})
					if err == nil {
						rawConn.WriteTo(packedAck, from)
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

				session.SessionSPIMu.RLock()
				ciph := session.Cipher
				sSPI := session.SessionSPI
				session.SessionSPIMu.RUnlock()

				if ciph == nil || sSPI == 0 {
					continue
				}

				seq := session.Seq.Add(1)
				packed, err := ciph.Pack(sSPI, seq, esp.ProtoIPv4, buf[:n])
				if err != nil {
					continue
				}

				if _, err := rawConn.WriteTo(packed, *targetAddr); err != nil {
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
		log.Printf("esp-server running. Listening: %s (Proto 50), TUN: disabled (no-tun mode), Reality v2 Forward Secrecy active", cfg.ListenAddr)
	} else {
		log.Printf("esp-server running. Listening: %s (Proto 50), Tun: %s (%s), Reality v2 Forward Secrecy + /16 Dynamic Random Pool active", cfg.ListenAddr, cfg.TunName, cidrStr)
	}
	wg.Wait()
	log.Printf("esp-server exited cleanly")
}
