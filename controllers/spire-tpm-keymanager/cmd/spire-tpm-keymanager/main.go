package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/sovereignite/sovereignite/controllers/internal/signing"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pluginConfig struct {
	ModulePath     string
	TokenLabel     string
	UserPIN        string
	KeyLabelPrefix string
	KnownKeyIDs    []string
}

type plugin struct {
	keymanagerv1.UnimplementedKeyManagerServer
	configv1.UnimplementedConfigServer

	mu  sync.RWMutex
	cfg pluginConfig
}

func main() {
	p := &plugin{}
	pluginmain.Serve(
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

func (p *plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := parseConfig(req.GetHclConfiguration())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.mu.Lock()
	p.cfg = cfg
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

func (p *plugin) Validate(ctx context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	if _, err := parseConfig(req.GetHclConfiguration()); err != nil {
		return &configv1.ValidateResponse{Valid: false, Notes: []string{err.Error()}}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

func (p *plugin) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	cfg, err := p.config()
	if err != nil {
		return nil, err
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}

	ref := cfg.refForKey(req.GetKeyId())
	if signer, closeFn, err := findSigner(ref); err == nil {
		defer closeFn()
		pub, err := publicKey(req.GetKeyId(), req.GetKeyType(), signer)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return &keymanagerv1.GenerateKeyResponse{PublicKey: pub}, nil
	}

	keyType := spireKeyType(req.GetKeyType())
	token, signer, err := signing.GeneratePKCS11Signer(ref, req.GetKeyId(), keyType)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	defer token.Close()

	pub, err := publicKey(req.GetKeyId(), req.GetKeyType(), signer)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &keymanagerv1.GenerateKeyResponse{PublicKey: pub}, nil
}

func (p *plugin) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	cfg, err := p.config()
	if err != nil {
		return nil, err
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_id is required")
	}
	signer, closeFn, err := findSigner(cfg.refForKey(req.GetKeyId()))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	defer closeFn()

	pub, err := publicKey(req.GetKeyId(), keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, signer)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &keymanagerv1.GetPublicKeyResponse{PublicKey: pub}, nil
}

func (p *plugin) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	cfg, err := p.config()
	if err != nil {
		return nil, err
	}
	out := &keymanagerv1.GetPublicKeysResponse{}
	for _, keyID := range cfg.KnownKeyIDs {
		signer, closeFn, err := findSigner(cfg.refForKey(keyID))
		if err != nil {
			continue
		}
		pub, err := publicKey(keyID, keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, signer)
		closeFn()
		if err == nil {
			out.PublicKeys = append(out.PublicKeys, pub)
		}
	}
	return out, nil
}

func (p *plugin) SignData(ctx context.Context, req *keymanagerv1.SignDataRequest) (*keymanagerv1.SignDataResponse, error) {
	cfg, err := p.config()
	if err != nil {
		return nil, err
	}
	signer, closeFn, err := findSigner(cfg.refForKey(req.GetKeyId()))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	defer closeFn()

	opts, err := signerOpts(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signature, err := signer.Sign(rand.Reader, req.GetData(), opts)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	pub, err := publicKey(req.GetKeyId(), keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE, signer)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &keymanagerv1.SignDataResponse{
		Signature:      signature,
		KeyFingerprint: pub.GetFingerprint(),
	}, nil
}

func (p *plugin) config() (pluginConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cfg.ModulePath == "" || p.cfg.TokenLabel == "" {
		return pluginConfig{}, status.Error(codes.FailedPrecondition, "plugin is not configured")
	}
	return p.cfg, nil
}

func parseConfig(hcl string) (pluginConfig, error) {
	cfg := pluginConfig{
		ModulePath:     firstNonEmpty(configValue(hcl, "module_path"), os.Getenv("TPM_PKCS11_MODULE"), "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so"),
		TokenLabel:     firstNonEmpty(configValue(hcl, "token_label"), os.Getenv("TPM_PKCS11_TOKEN_LABEL")),
		UserPIN:        firstNonEmpty(configValue(hcl, "user_pin"), os.Getenv("TPM_PKCS11_PIN")),
		KeyLabelPrefix: firstNonEmpty(configValue(hcl, "key_label_prefix"), os.Getenv("SPIRE_TPM_KEY_LABEL_PREFIX"), "sovereignite-spire-"),
		KnownKeyIDs:    csv(firstNonEmpty(configValue(hcl, "known_key_ids"), os.Getenv("SPIRE_TPM_KNOWN_KEY_IDS"))),
	}
	if cfg.ModulePath == "" {
		return pluginConfig{}, fmt.Errorf("module_path is required")
	}
	if cfg.TokenLabel == "" {
		return pluginConfig{}, fmt.Errorf("token_label is required")
	}
	return cfg, nil
}

func (c pluginConfig) refForKey(keyID string) signing.PKCS11Ref {
	return signing.PKCS11Ref{
		ModulePath: c.ModulePath,
		TokenLabel: c.TokenLabel,
		KeyLabel:   c.KeyLabelPrefix + keyID,
		UserPIN:    c.UserPIN,
	}
}

func findSigner(ref signing.PKCS11Ref) (crypto.Signer, func(), error) {
	ctx, signer, err := signing.LoadPKCS11Signer(ref)
	if err != nil {
		return nil, func() {}, err
	}
	return signer, func() { _ = ctx.Close() }, nil
}

func publicKey(id string, requested keymanagerv1.KeyType, signer crypto.Signer) (*keymanagerv1.PublicKey, error) {
	pkixData, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(pkixData)
	keyType := requested
	if keyType == keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE {
		keyType = keyTypeFromPublic(signer.Public())
	}
	return &keymanagerv1.PublicKey{
		Id:          id,
		Type:        keyType,
		PkixData:    pkixData,
		Fingerprint: hex.EncodeToString(fingerprint[:]),
	}, nil
}

func keyTypeFromPublic(public crypto.PublicKey) keymanagerv1.KeyType {
	switch k := public.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() > 2048 {
			return keymanagerv1.KeyType_RSA_4096
		}
		return keymanagerv1.KeyType_RSA_2048
	default:
		name := signing.KeyTypeFromPublicKey(public)
		switch name {
		case "ec-p384":
			return keymanagerv1.KeyType_EC_P384
		case "ec-p256":
			return keymanagerv1.KeyType_EC_P256
		default:
			return keymanagerv1.KeyType_UNSPECIFIED_KEY_TYPE
		}
	}
}

func spireKeyType(keyType keymanagerv1.KeyType) string {
	switch keyType {
	case keymanagerv1.KeyType_EC_P384:
		return "ec-p384"
	case keymanagerv1.KeyType_RSA_2048:
		return "rsa-2048"
	case keymanagerv1.KeyType_RSA_4096:
		return "rsa-4096"
	default:
		return "ec-p256"
	}
}

func signerOpts(req *keymanagerv1.SignDataRequest) (crypto.SignerOpts, error) {
	if pss := req.GetPssOptions(); pss != nil {
		hash, err := hashAlgorithm(pss.GetHashAlgorithm())
		if err != nil {
			return nil, err
		}
		saltLength := int(pss.GetSaltLength())
		if saltLength == 0 {
			saltLength = rsa.PSSSaltLengthEqualsHash
		}
		return &rsa.PSSOptions{SaltLength: saltLength, Hash: hash}, nil
	}
	return hashAlgorithm(req.GetHashAlgorithm())
}

func hashAlgorithm(alg keymanagerv1.HashAlgorithm) (crypto.Hash, error) {
	switch alg {
	case keymanagerv1.HashAlgorithm_SHA256, keymanagerv1.HashAlgorithm_UNSPECIFIED_HASH_ALGORITHM:
		_ = sha256.Size
		return crypto.SHA256, nil
	case keymanagerv1.HashAlgorithm_SHA384:
		_ = sha512.Size384
		return crypto.SHA384, nil
	case keymanagerv1.HashAlgorithm_SHA512:
		_ = sha512.Size
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm %s", alg.String())
	}
}

func configValue(hcl, key string) string {
	re := regexp.MustCompile(`(?m)\b` + regexp.QuoteMeta(key) + `\s*=\s*"([^"]*)"`)
	match := re.FindStringSubmatch(hcl)
	if len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func csv(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
