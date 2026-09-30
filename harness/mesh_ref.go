// mesh_ref - dev-time oracle for the solidSNAKE mesh.
//
// Modes (driven by scripts/interop.sh):
//
//	gob-gen                encode the MeshHeartbeat fixtures with the reference gob encoder
//	                       ("hex<TAB>canonical-json" per line)
//	gob-check <file>       decode "hex" lines with encoding/gob and print canonical JSON
//	                       (proves Go reads the bytes the solidSNAKE encoder produced)
//	sig-check <file>       verify an Ed25519 heartbeat signature (pub/payload/sig hex lines)
//	peer ...               run a real mesh.Node and print JSON events, exactly like
//	                       `test_mesh --peer` does on the solidSNAKE side
//
// Never built into any solidSNAKE binary.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/mesh"
	"git.churchofmalware.org/ek0mssavi0r/Ranger-C3/internal/protocol"
)

// Heartbeat fixtures shared with tests/test_mesh.cpp (hex + values).
func fixtures() []protocol.MeshHeartbeat {
	empty := protocol.MeshHeartbeat{}
	nodeid := protocol.MeshHeartbeat{NodeID: "c2-abc"}
	strings := protocol.MeshHeartbeat{NodeID: "c2-abc", Addr: "127.0.0.1:9000", Timestamp: 1758350000}
	implants := protocol.MeshHeartbeat{NodeID: "n", Implants: []string{"i1", "i2"}}
	full := protocol.MeshHeartbeat{
		NodeID:    "c2-1122334455",
		Addr:      ":9000",
		Implants:  []string{"a"},
		Timestamp: -1,
		Signature: []byte{0xff},
	}
	return []protocol.MeshHeartbeat{empty, nodeid, strings, implants, full}
}

func canonical(hb protocol.MeshHeartbeat) string {
	// Same key set the solidSNAKE side prints (interop canonicalises before diffing).
	type view struct {
		NodeID     string   `json:"node_id"`
		Addr       string   `json:"addr"`
		ImplantIDs []string `json:"implant_ids"`
		TS         int64    `json:"ts"`
		SigHex     string   `json:"sig_hex"`
	}
	ids := hb.Implants
	if ids == nil {
		ids = []string{}
	}
	b, _ := json.Marshal(view{
		NodeID:     hb.NodeID,
		Addr:       hb.Addr,
		ImplantIDs: ids,
		TS:         hb.Timestamp,
		SigHex:     hex.EncodeToString(hb.Signature),
	})
	return string(b)
}

func encodeStream(hb protocol.MeshHeartbeat) ([]byte, error) {
	var buf strings.Builder
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(hb); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func gobGen() {
	for _, hb := range fixtures() {
		b, err := encodeStream(hb)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode:", err)
			os.Exit(1)
		}
		fmt.Printf("%s\t%s\n", hex.EncodeToString(b), canonical(hb))
	}
}

func gobCheck(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		raw, err := hex.DecodeString(fields[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex:", err)
			os.Exit(1)
		}
		var hb protocol.MeshHeartbeat
		if err := gob.NewDecoder(strings.NewReader(string(raw))).Decode(&hb); err != nil {
			fmt.Fprintln(os.Stderr, "gob decode:", err)
			os.Exit(1)
		}
		fmt.Println(canonical(hb))
	}
}

func sigCheck(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		fmt.Fprintln(os.Stderr, "sig-check expects pub/payload/sig hex lines")
		os.Exit(1)
	}
	pub, err1 := hex.DecodeString(strings.TrimSpace(lines[0]))
	msg, err2 := hex.DecodeString(strings.TrimSpace(lines[1]))
	sig, err3 := hex.DecodeString(strings.TrimSpace(lines[2]))
	if err1 != nil || err2 != nil || err3 != nil {
		fmt.Fprintln(os.Stderr, "bad hex", err1, err2, err3)
		os.Exit(1)
	}
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		fmt.Fprintln(os.Stderr, "bad key/signature length")
		os.Exit(1)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		fmt.Fprintln(os.Stderr, "signature does NOT verify")
		os.Exit(1)
	}
	fmt.Println("sig ok")
}

// runPeer mirrors `test_mesh --peer`: JSON event lines on stdout, the reference mesh
// package doing the real work.
func runPeer(args []string) {
	fs := flag.NewFlagSet("peer", flag.ExitOnError)
	id := fs.String("id", "", "node id")
	listen := fs.String("listen", "127.0.0.1:0", "mesh listen address")
	bootstrap := fs.String("bootstrap", "", "comma separated bootstrap peers")
	seconds := fs.Int("seconds", 5, "run time")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "--id is required")
		os.Exit(1)
	}

	// The real listen port is only known after Start; the C3 package binds inside Start, so
	// bind first with a throwaway listener? No - mirror the solidSNAKE flow: Start binds and the
	// port is discovered by asking the OS through a temporary probe below.
	port := discoverPort(*listen)
	cfg := mesh.Config{
		NodeID:     *id,
		ListenAddr: *listen,
		TLSCert:    meshCert(*id),
	}
	if port > 0 {
		cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	if *bootstrap != "" {
		cfg.Bootstrap = strings.Split(*bootstrap, ",")
	}
	cfg.OnPeerJoin = func(n *protocol.MeshNode) {
		emit(map[string]any{
			"event":    "join",
			"id":       n.ID,
			"addr":     n.Addr,
			"implants": n.Implants,
			"version":  n.Version,
		})
	}
	cfg.OnHeartbeat = func(hb *protocol.MeshHeartbeat) {
		ids := hb.Implants
		if ids == nil {
			ids = []string{}
		}
		emit(map[string]any{
			"event":     "heartbeat",
			"node_id":   hb.NodeID,
			"addr":      hb.Addr,
			"implants":  ids,
			"sig_len":   len(hb.Signature),
		})
	}
	cfg.OnPeerLeave = func(peerID string) {
		emit(map[string]any{"event": "leave", "id": peerID})
	}

	node := mesh.NewNode(cfg)
	if err := node.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "mesh:", err)
		os.Exit(1)
	}
	emit(map[string]any{"event": "listen", "port": port})
	time.Sleep(time.Duration(*seconds) * time.Second)
	node.Stop()
}

// meshCert mirrors cmd/c2's generateMeshCert (the reference C2 builds its mesh certificate
// the same way, in memory, once per start).
func meshCert(nodeID string) tls.Certificate {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mesh cert:", err)
		os.Exit(1)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"Ranger Mesh"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mesh cert:", err)
		os.Exit(1)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: template}
}

// discoverPort binds a throwaway listener to learn the ephemeral port for ":0" style
// addresses, then releases it so mesh.Start can bind it again.
func discoverPort(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return 0
	}
	if addr[idx+1:] != "0" {
		return 0
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func emit(v map[string]any) {
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
	os.Stdout.Sync()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mesh_ref gob-gen|gob-check <file>|sig-check <file>|peer ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gob-gen":
		gobGen()
	case "gob-check":
		gobCheck(os.Args[2])
	case "sig-check":
		sigCheck(os.Args[2])
	case "peer":
		runPeer(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}
