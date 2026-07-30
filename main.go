package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Tunnel struct {
	name string
	net  *netstack.Net
	dev  *device.Device
}

type tunnelConfig struct {
	name       string
	privateKey string
	publicKey  string
	endpoint   string
	addresses  []string
	dns        []string
}

func main() {
	configDir := flag.String("config-dir", "", "directory of WireGuard .conf files (one server per file)")
	rotateEvery := flag.Int("rotate-every", 0, "rotate to the next tunnel after this many requests")
	rotateIdle := flag.Duration("rotate-idle", 0, "rotate to the next tunnel if idle for this long, e.g. 30s")
	listen := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	flag.Parse()

	if *configDir == "" {
		log.Fatal("-config-dir is required")
	}
	if *rotateEvery <= 0 && *rotateIdle <= 0 {
		log.Fatal("at least one of -rotate-every or -rotate-idle must be set")
	}

	files, err := filepath.Glob(filepath.Join(*configDir, "*.conf"))
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatalf("no .conf files found in %s", *configDir)
	}
	rand.Shuffle(len(files), func(i, j int) { files[i], files[j] = files[j], files[i] })

	var configs []*tunnelConfig
	for _, f := range files {
		cfg, err := parseConfig(strings.TrimSuffix(filepath.Base(f), ".conf"), f)
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		configs = append(configs, cfg)
	}
	log.Printf("loaded %d tunnel config(s)", len(configs))

	current, err := connectTunnel(configs[0])
	if err != nil {
		log.Fatalf("%s: %v", configs[0].name, err)
	}
	log.Printf("connected tunnel %q", current.name)

	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	idx, count, last, inFlight := 0, 0, time.Now(), 0

	rotateIfDue := func() {
		for {
			idleDue := *rotateIdle > 0 && time.Since(last) >= *rotateIdle
			countDue := *rotateEvery > 0 && count >= *rotateEvery
			if !idleDue && !countDue {
				return
			}

			if inFlight > 0 {
				cond.Wait()
				continue
			}

			reason := "request count"
			if idleDue {
				reason = "idle"
			}

			current.dev.Close()
			idx = (idx + 1) % len(configs)
			t, err := connectTunnel(configs[idx])
			if err != nil {
				log.Fatalf("%s: %v", configs[idx].name, err)
			}

			current = t
			count = 0
			last = time.Now()
			log.Printf("rotated to tunnel %q (%s)", current.name, reason)
			return
		}
	}

	next := func() *Tunnel {
		mu.Lock()
		defer mu.Unlock()

		rotateIfDue()

		last = time.Now()
		count++
		inFlight++

		return current
	}

	release := func() {
		mu.Lock()
		inFlight--
		if inFlight == 0 {
			cond.Broadcast()
		}
		mu.Unlock()
	}

	srv := socks5.NewServer(
		socks5.WithResolver(passthroughResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			t := next()
			dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			c, err := t.net.DialContext(dialCtx, network, addr)
			if err != nil {
				release()
				return nil, err
			}

			return &releaseOnClose{Conn: c, release: release}, nil
		}),
	)

	log.Printf("listening on %s", *listen)
	log.Fatal(srv.ListenAndServe("tcp", *listen))
}

type passthroughResolver struct{}

func (passthroughResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

type releaseOnClose struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *releaseOnClose) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func parseConfig(name, path string) (*tunnelConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &tunnelConfig{name: name}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)

		switch key {
		case "privatekey":
			cfg.privateKey = val
		case "address":
			cfg.addresses = append(cfg.addresses, splitTrim(val)...)
		case "dns":
			cfg.dns = append(cfg.dns, splitTrim(val)...)
		case "publickey":
			cfg.publicKey = val
		case "endpoint":
			cfg.endpoint = val
		}
	}

	if cfg.privateKey == "" || cfg.publicKey == "" || cfg.endpoint == "" || len(cfg.addresses) == 0 || len(cfg.dns) == 0 {
		return nil, fmt.Errorf("config must set PrivateKey, Address, DNS, PublicKey, and Endpoint")
	}

	return cfg, nil
}

func splitTrim(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func connectTunnel(cfg *tunnelConfig) (*Tunnel, error) {
	privHex, err := keyToHex(cfg.privateKey)
	if err != nil {
		return nil, fmt.Errorf("PrivateKey: %w", err)
	}
	pubHex, err := keyToHex(cfg.publicKey)
	if err != nil {
		return nil, fmt.Errorf("PublicKey: %w", err)
	}
	endpointAddr, err := netip.ParseAddrPort(cfg.endpoint)
	if err != nil {
		return nil, fmt.Errorf("Endpoint: %w", err)
	}
	localAddrs, err := parseAddrs(cfg.addresses)
	if err != nil {
		return nil, err
	}
	dnsAddrs, err := parseAddrs(cfg.dns)
	if err != nil {
		return nil, err
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, 1420)
	if err != nil {
		return nil, err
	}

	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		privHex, pubHex, endpointAddr)

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "("+cfg.name+") "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	return &Tunnel{name: cfg.name, net: tnet, dev: dev}, nil
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid key %q", b64)
	}
	return hex.EncodeToString(raw), nil
}

func parseAddrs(in []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range in {
		s, _, _ = strings.Cut(s, "/")
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q", s)
		}
		out = append(out, addr)
	}
	return out, nil
}
