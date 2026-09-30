// Dev-only oracle for the solidSNAKE C2 certificate work. NOT part of the product.
//
//   go run ./cmd/certref dump <cert.pem>
//   go run ./cmd/certref roundtrip <cert.pem> <key.pem> <servername>
//
// `dump` prints the canonical properties of a certificate (Go's own x509 parser is the oracle, so
// a certificate solidSNAKE produced must survive it). `roundtrip` runs a real TLS handshake: an in-process
// Go TLS server using the given pair, with a Go client that trusts only that certificate.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func loadCert(path string) *x509.Certificate {
	raw, err := os.ReadFile(path)
	if err != nil {
		die("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		die("%s: no PEM block", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		die("parse %s: %v", path, err)
	}
	return c
}

var keyUsageNames = []string{
	"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment",
	"keyAgreement", "certSign", "crlSign", "encipherOnly", "decipherOnly",
}

func keyUsage(c *x509.Certificate) []string {
	var out []string
	for i, name := range keyUsageNames {
		if c.KeyUsage&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func extKeyUsage(c *x509.Certificate) []string {
	var out []string
	for _, e := range c.ExtKeyUsage {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "serverAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "clientAuth")
		default:
			out = append(out, fmt.Sprintf("other(%d)", int(e)))
		}
	}
	return out
}

func dump(path string) {
	c := loadCert(path)

	ips := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)
	dns := append([]string(nil), c.DNSNames...)
	sort.Strings(dns)
	ku := keyUsage(c)
	eku := extKeyUsage(c)
	sort.Strings(ku)
	sort.Strings(eku)

	out := map[string]any{
		"version":             c.Version,
		"subject_cn":          c.Subject.CommonName,
		"subject_o":           strings.Join(c.Subject.Organization, ","),
		"serial_bits":         c.SerialNumber.BitLen(),
		"serial_positive":     c.SerialNumber.Sign() > 0,
		"key_algorithm":       c.PublicKeyAlgorithm.String(),
		"signature_algorithm": c.SignatureAlgorithm.String(),
		"dns_names":           dns,
		"ip_addresses":        ips,
		"key_usage":           ku,
		"ext_key_usage":       eku,
		"basic_constraints":   c.BasicConstraintsValid,
		"is_ca":               c.IsCA,
		"basic_constraints_critical": hasCriticalExt(c, "2.5.29.19"),
		"key_usage_critical":         hasCriticalExt(c, "2.5.29.15"),
		"eku_critical":               hasCriticalExt(c, "2.5.29.37"),
		"san_critical":               hasCriticalExt(c, "2.5.29.17"),
		"validity_seconds":           int64(c.NotAfter.Sub(c.NotBefore).Seconds()),
		"self_signed":                c.CheckSignatureFrom(c) == nil,
		"dnsnames_present":           len(c.DNSNames) > 0,
	}
	// NotBefore is now-1h; report the offset from now so the two sides can be compared.
	out["not_before_offset_secs"] = int64(time.Until(c.NotBefore).Seconds())
	out["not_after_offset_secs"] = int64(time.Until(c.NotAfter).Seconds())

	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

func hasCriticalExt(c *x509.Certificate, oid string) bool {
	for _, e := range c.Extensions {
		if e.Id.String() == oid {
			return e.Critical
		}
	}
	return false
}

func roundtrip(certPath, keyPath, serverName string) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		die("LoadX509KeyPair: %v", err)
	}
	leaf := loadCert(certPath)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		die("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		Served   bool
		Server   string
		Err      string
		Verified bool
	}
	done := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- result{Err: err.Error()}
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			done <- result{Err: err.Error()}
			return
		}
		io.Copy(io.Discard, tc)
		done <- result{Served: true, Server: tc.ConnectionState().ServerName}
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
	})
	if err != nil {
		die("client handshake: %v", err)
	}
	state := conn.ConnectionState()
	conn.Close()
	<-done

	out := map[string]any{
		"handshake":     true,
		"server_name":   serverName,
		"verified":      len(state.VerifiedChains) > 0,
		"peer_dns":      leaf.DNSNames,
		"peer_subject":  leaf.Subject.String(),
		"chain_lengths": chainLengths(state.VerifiedChains),
		"expired":       time.Now().After(leaf.NotAfter) || time.Now().Before(leaf.NotBefore),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	_ = net.IPv4len
}

func chainLengths(chains [][]*x509.Certificate) []int {
	out := make([]int, 0, len(chains))
	for _, c := range chains {
		out = append(out, len(c))
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		die("usage: certref dump <cert.pem> | certref roundtrip <cert.pem> <key.pem> <servername>")
	}
	switch os.Args[1] {
	case "dump":
		if len(os.Args) != 3 {
			die("usage: certref dump <cert.pem>")
		}
		dump(os.Args[2])
	case "roundtrip":
		if len(os.Args) != 5 {
			die("usage: certref roundtrip <cert.pem> <key.pem> <servername>")
		}
		roundtrip(os.Args[2], os.Args[3], os.Args[4])
	default:
		die("unknown mode %q", os.Args[1])
	}
}
