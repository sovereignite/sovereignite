package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

const devIDKeyAttributes = tpm2.FlagSign |
	tpm2.FlagFixedTPM |
	tpm2.FlagFixedParent |
	tpm2.FlagSensitiveDataOrigin |
	tpm2.FlagUserWithAuth

type options struct {
	device        string
	outDir        string
	keyType       string
	ownerPassword string
	devIDPassword string
	force         bool
}

func main() {
	opts := options{}
	flag.StringVar(&opts.device, "device", "/dev/tpmrm0", "TPM device path")
	flag.StringVar(&opts.outDir, "out-dir", "/var/lib/sovereignite/tpm", "output directory")
	flag.StringVar(&opts.keyType, "key-type", "rsa", "DevID key type: rsa or ecc")
	flag.StringVar(&opts.ownerPassword, "owner-password", "", "TPM owner hierarchy password")
	flag.StringVar(&opts.devIDPassword, "devid-password", "", "DevID key password")
	flag.BoolVar(&opts.force, "force", false, "replace existing DevID blobs")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "tpm-devid-provisioner: %v\n", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	if err := os.MkdirAll(opts.outDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	privPath := filepath.Join(opts.outDir, "devid.priv.blob")
	pubPath := filepath.Join(opts.outDir, "devid.pub.blob")
	pubPEMPath := filepath.Join(opts.outDir, "devid.pub.pem")

	if !opts.force {
		privExists, err := fileExists(privPath)
		if err != nil {
			return err
		}
		pubExists, err := fileExists(pubPath)
		if err != nil {
			return err
		}
		if privExists && pubExists {
			pubBlob, err := os.ReadFile(pubPath)
			if err != nil {
				return fmt.Errorf("read existing public blob: %w", err)
			}
			return writePublicPEM(pubPEMPath, pubBlob)
		}
	}

	rwc, err := tpm2.OpenTPM(opts.device)
	if err != nil {
		return fmt.Errorf("open TPM %q: %w", opts.device, err)
	}
	defer rwc.Close()

	keyTemplate, srkTemplate, err := templates(opts.keyType)
	if err != nil {
		return err
	}

	srkHandle, _, _, _, _, _, err := tpm2.CreatePrimaryEx(
		rwc,
		tpm2.HandleOwner,
		tpm2.PCRSelection{},
		opts.ownerPassword,
		"",
		srkTemplate,
	)
	if err != nil {
		return fmt.Errorf("create SRK: %w", err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	privBlob, pubBlob, _, _, _, err := tpm2.CreateKey(
		rwc,
		srkHandle,
		tpm2.PCRSelection{},
		"",
		opts.devIDPassword,
		keyTemplate,
	)
	if err != nil {
		return fmt.Errorf("create DevID key: %w", err)
	}

	if err := os.WriteFile(privPath, privBlob, 0o600); err != nil {
		return fmt.Errorf("write private blob: %w", err)
	}
	if err := os.WriteFile(pubPath, pubBlob, 0o644); err != nil {
		return fmt.Errorf("write public blob: %w", err)
	}
	if err := writePublicPEM(pubPEMPath, pubBlob); err != nil {
		return err
	}

	return nil
}

func templates(keyType string) (tpm2.Public, tpm2.Public, error) {
	switch strings.ToLower(keyType) {
	case "rsa":
		keyTemplate := client.AKTemplateRSA()
		keyTemplate.Attributes = devIDKeyAttributes
		return keyTemplate, srkTemplateHighRSA(), nil
	case "ecc":
		keyTemplate := client.AKTemplateECC()
		keyTemplate.Attributes = devIDKeyAttributes
		return keyTemplate, srkTemplateHighECC(), nil
	default:
		return tpm2.Public{}, tpm2.Public{}, fmt.Errorf("unsupported key type %q", keyType)
	}
}

func srkTemplateHighRSA() tpm2.Public {
	template := client.SRKTemplateRSA()
	template.RSAParameters.ModulusRaw = []byte{}
	return template
}

func srkTemplateHighECC() tpm2.Public {
	template := client.SRKTemplateECC()
	template.ECCParameters.Point.XRaw = []byte{}
	template.ECCParameters.Point.YRaw = []byte{}
	return template
}

func writePublicPEM(path string, pubBlob []byte) error {
	pub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		return fmt.Errorf("decode public blob: %w", err)
	}
	publicKey, err := pub.Key()
	if err != nil {
		return fmt.Errorf("extract public key: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if block == nil {
		return errors.New("encode public key PEM")
	}
	if err := os.WriteFile(path, block, 0o644); err != nil {
		return fmt.Errorf("write public key PEM: %w", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
}
