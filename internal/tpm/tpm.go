package tpm

import (
	"crypto"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type Backend struct {
	mu       sync.Mutex
	rwc      io.ReadWriteCloser
	device   string
	sessions []Session
}

type Session struct {
	Handle tpmutil.Handle
}

type KeyHandle struct {
	handle    tpmutil.Handle
	publicKey crypto.PublicKey
}

func Open(device string) (*Backend, error) {
	rwc, err := tpm2.OpenTPM(device)
	if err != nil {
		return nil, fmt.Errorf("open TPM %q: %w", device, err)
	}
	return &Backend{
		rwc:    rwc,
		device: device,
	}, nil
}

func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rwc != nil {
		err := b.rwc.Close()
		b.rwc = nil
		return err
	}
	return nil
}

func (b *Backend) ReadPublic(handle tpmutil.Handle) (tpm2.Public, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rwc == nil {
		return tpm2.Public{}, nil, fmt.Errorf("TPM backend not open")
	}
	pub, _, _, err := tpm2.ReadPublic(b.rwc, handle)
	if err != nil {
		return tpm2.Public{}, nil, fmt.Errorf("read public area handle 0x%x: %w", handle, err)
	}
	pubBlob, err := pub.Encode()
	if err != nil {
		return tpm2.Public{}, nil, fmt.Errorf("encode public area: %w", err)
	}
	return pub, pubBlob, nil
}
