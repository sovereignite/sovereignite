package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
)

type PKCS11Ref struct {
	ModulePath string
	TokenLabel string
	KeyLabel   string
	UserPIN    string
}

type Options struct {
	Usages                    []string
	MaxDuration               time.Duration
	RequestedDuration         time.Duration
	AllowedDNSDomains         []string
	AllowedSpiffeTrustDomains []string
	AllowWildcardDNSNames     bool
	AllowCA                   bool
	IsCA                      bool
	MaxPathLen                int
	SubjectRegexes            []string
}

type IssuedCertificate struct {
	CertificatePEM string
	CAPEM          string
	Serial         string
}

func SignCSR(csrBytes []byte, caPEM string, ref PKCS11Ref, opts Options) (*IssuedCertificate, error) {
	csr, err := ParseCSR(csrBytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature check failed: %w", err)
	}
	if err := ValidateCSR(csr, opts); err != nil {
		return nil, err
	}
	if opts.IsCA && !opts.AllowCA {
		return nil, errors.New("CA certificate requested but CA issuance is not allowed")
	}

	caCert, err := ParseCertificatePEM([]byte(caPEM))
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	ctx, signer, err := LoadPKCS11Signer(ref)
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	now := time.Now().UTC()
	duration := opts.RequestedDuration
	if duration <= 0 || duration > opts.MaxDuration && opts.MaxDuration > 0 {
		duration = opts.MaxDuration
	}
	if duration <= 0 {
		duration = 24 * time.Hour
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}

	keyUsage, extKeyUsage, err := Usages(opts.Usages, opts.AllowCA)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
		EmailAddresses:        csr.EmailAddresses,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(duration),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
	}
	if opts.IsCA {
		template.MaxPathLen = opts.MaxPathLen
		template.MaxPathLenZero = opts.MaxPathLen == 0
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate with PKCS#11 signer: %w", err)
	}

	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &IssuedCertificate{
		CertificatePEM: leafPEM + strings.TrimSpace(caPEM) + "\n",
		CAPEM:          strings.TrimSpace(caPEM) + "\n",
		Serial:         strings.ToUpper(serial.Text(16)),
	}, nil
}

func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil {
		data = decoded
	}
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
		}
		data = block.Bytes
	}
	return x509.ParseCertificateRequest(data)
}

func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("missing certificate PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func LoadPKCS11Signer(ref PKCS11Ref) (*crypto11.Context, crypto.Signer, error) {
	if ref.ModulePath == "" || ref.TokenLabel == "" || ref.KeyLabel == "" {
		return nil, nil, errors.New("modulePath, tokenLabel, and keyLabel are required")
	}
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:        ref.ModulePath,
		TokenLabel:  ref.TokenLabel,
		Pin:         ref.UserPIN,
		MaxSessions: 16,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("configure PKCS#11 token %q: %w", ref.TokenLabel, err)
	}
	signer, err := ctx.FindKeyPair(nil, []byte(ref.KeyLabel))
	if err != nil {
		ctx.Close()
		return nil, nil, fmt.Errorf("find PKCS#11 key %q: %w", ref.KeyLabel, err)
	}
	if signer == nil {
		ctx.Close()
		return nil, nil, fmt.Errorf("PKCS#11 key %q not found", ref.KeyLabel)
	}
	return ctx, signer, nil
}

func GeneratePKCS11Signer(ref PKCS11Ref, keyID, keyType string) (*crypto11.Context, crypto.Signer, error) {
	if ref.ModulePath == "" || ref.TokenLabel == "" || ref.KeyLabel == "" {
		return nil, nil, errors.New("modulePath, tokenLabel, and keyLabel are required")
	}
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:        ref.ModulePath,
		TokenLabel:  ref.TokenLabel,
		Pin:         ref.UserPIN,
		MaxSessions: 16,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("configure PKCS#11 token %q: %w", ref.TokenLabel, err)
	}
	id := []byte(keyID)
	label := []byte(ref.KeyLabel)
	var signer crypto.Signer
	switch strings.ToLower(keyType) {
	case "", "ec-p256", "ec256", "ecdsa-p256":
		signer, err = ctx.GenerateECDSAKeyPairWithLabel(id, label, elliptic.P256())
	case "ec-p384", "ec384", "ecdsa-p384":
		signer, err = ctx.GenerateECDSAKeyPairWithLabel(id, label, elliptic.P384())
	case "rsa-2048", "rsa2048":
		signer, err = ctx.GenerateRSAKeyPairWithLabel(id, label, 2048)
	case "rsa-4096", "rsa4096":
		signer, err = ctx.GenerateRSAKeyPairWithLabel(id, label, 4096)
	default:
		err = fmt.Errorf("unsupported key type %q", keyType)
	}
	if err != nil {
		ctx.Close()
		return nil, nil, err
	}
	return ctx, signer, nil
}

func PublicKeyDER(signer crypto.Signer) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(signer.Public())
}

func ValidateCSR(csr *x509.CertificateRequest, opts Options) error {
	if !opts.AllowWildcardDNSNames {
		for _, name := range csr.DNSNames {
			if strings.HasPrefix(name, "*.") {
				return fmt.Errorf("wildcard DNS name %q is not allowed", name)
			}
		}
	}
	for _, name := range csr.DNSNames {
		if len(opts.AllowedDNSDomains) > 0 && !dnsNameAllowed(name, opts.AllowedDNSDomains) {
			return fmt.Errorf("DNS name %q is outside allowed domains", name)
		}
	}
	for _, uri := range csr.URIs {
		if uri.Scheme == "spiffe" && len(opts.AllowedSpiffeTrustDomains) > 0 && !stringAllowed(uri.Host, opts.AllowedSpiffeTrustDomains) {
			return fmt.Errorf("SPIFFE trust domain %q is not allowed", uri.Host)
		}
	}
	return nil
}

func Usages(usages []string, allowCA bool) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var keyUsage x509.KeyUsage
	var ext []x509.ExtKeyUsage
	for _, usage := range usages {
		switch normalizeUsage(usage) {
		case "digital signature", "signing":
			keyUsage |= x509.KeyUsageDigitalSignature
		case "key encipherment":
			keyUsage |= x509.KeyUsageKeyEncipherment
		case "server auth":
			ext = append(ext, x509.ExtKeyUsageServerAuth)
		case "client auth":
			ext = append(ext, x509.ExtKeyUsageClientAuth)
		case "cert sign":
			if !allowCA {
				return 0, nil, fmt.Errorf("CA usage %q is not allowed", usage)
			}
			keyUsage |= x509.KeyUsageCertSign
		case "crl sign":
			if !allowCA {
				return 0, nil, fmt.Errorf("CA usage %q is not allowed", usage)
			}
			keyUsage |= x509.KeyUsageCRLSign
		case "":
		default:
			return 0, nil, fmt.Errorf("unsupported usage %q", usage)
		}
	}
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageDigitalSignature
	}
	return keyUsage, ext, nil
}

func KeyFingerprint(signer crypto.Signer) ([]byte, error) {
	pubDER, err := PublicKeyDER(signer)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubDER)
	return sum[:], nil
}

func KeyTypeFromPublicKey(public crypto.PublicKey) string {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return "ec-p256"
		case elliptic.P384():
			return "ec-p384"
		default:
			return "ec"
		}
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", key.N.BitLen())
	default:
		return fmt.Sprintf("%T", public)
	}
}

func normalizeUsage(usage string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(usage, "_", " ")))
}

func dnsNameAllowed(name string, domains []string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(name, "*.")), ".")
	for _, domain := range domains {
		domain = strings.TrimSuffix(strings.ToLower(domain), ".")
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}
	return false
}

func stringAllowed(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func ParseDuration(value string) time.Duration {
	if value == "" {
		return 0
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func DNSNamesFromCSR(csr *x509.CertificateRequest) []string {
	out := append([]string{}, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		out = append(out, ip.String())
	}
	for _, uri := range csr.URIs {
		out = append(out, uri.String())
	}
	return out
}

func IPAddressesFromStrings(values []string) []net.IP {
	var out []net.IP
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func URIsFromStrings(values []string) []*url.URL {
	var out []*url.URL
	for _, value := range values {
		uri, err := url.Parse(value)
		if err == nil && uri.Scheme != "" {
			out = append(out, uri)
		}
	}
	return out
}

func SubjectCommonName(subject pkix.Name) string {
	return subject.CommonName
}
