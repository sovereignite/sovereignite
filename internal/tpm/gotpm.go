// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2026 Sovereignite contributors

package tpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// GoTPMConfig configures the typed Linux github.com/google/go-tpm adapter.
//
// Auth values are copied into locked adapter state and are never returned or
// persisted by this package. Every configured persistent handle requires its
// own high-entropy authorization value.
type GoTPMConfig struct {
	DevicePath         string
	OwnerAuth          []byte
	ObjectAuthByHandle map[Handle][]byte
}

type goTPMBackend struct {
	mu sync.Mutex

	device             transport.TPMCloser
	ownerAuth          []byte
	objectAuthByHandle map[Handle][]byte
	closed             bool
}

const authorizationValueBytes = sha256.Size

// OpenGoTPM opens exactly the configured Linux TPM device. It has no simulator,
// TCP, software-key, alternate-device, or algorithm-downgrade fallback.
func OpenGoTPM(config GoTPMConfig) (Backend, error) {
	devicePath := strings.TrimSpace(config.DevicePath)
	if devicePath == "" {
		return nil, errors.New("TPM device path is required")
	}
	if err := validateAuthorizationValue("owner", config.OwnerAuth); err != nil {
		return nil, err
	}
	if len(config.ObjectAuthByHandle) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one per-handle object authorization is required",
			ErrAuthorizationUnavailable,
		)
	}
	seenHandles := make([]Handle, 0, len(config.ObjectAuthByHandle))
	seenAuthorizations := make([][]byte, 0, len(config.ObjectAuthByHandle))
	for handle, auth := range config.ObjectAuthByHandle {
		if !handle.IsPersistent() {
			return nil, fmt.Errorf(
				"%w: object authorization handle %#x is not persistent",
				ErrAuthorizationUnavailable,
				uint32(handle),
			)
		}
		if err := validateAuthorizationValue(
			fmt.Sprintf("object handle %#x", uint32(handle)),
			auth,
		); err != nil {
			return nil, err
		}
		if bytes.Equal(auth, config.OwnerAuth) {
			return nil, fmt.Errorf(
				"%w: owner and object authorization values must be separated",
				ErrAuthorizationUnavailable,
			)
		}
		for index, existingAuth := range seenAuthorizations {
			if bytes.Equal(auth, existingAuth) {
				return nil, fmt.Errorf(
					"%w: handles %#x and %#x share an authorization value",
					ErrAuthorizationUnavailable,
					uint32(seenHandles[index]),
					uint32(handle),
				)
			}
		}
		seenHandles = append(seenHandles, handle)
		seenAuthorizations = append(seenAuthorizations, auth)
	}
	objectAuthByHandle := make(map[Handle][]byte, len(config.ObjectAuthByHandle))
	for handle, auth := range config.ObjectAuthByHandle {
		objectAuthByHandle[handle] = slices.Clone(auth)
	}
	device, err := linuxtpm.Open(devicePath)
	if err != nil {
		for handle, auth := range objectAuthByHandle {
			clear(auth)
			delete(objectAuthByHandle, handle)
		}
		return nil, fmt.Errorf("open Linux TPM device %q: %w", devicePath, err)
	}
	return &goTPMBackend{
		device:             device,
		ownerAuth:          slices.Clone(config.OwnerAuth),
		objectAuthByHandle: objectAuthByHandle,
	}, nil
}

func (b *goTPMBackend) Supports(
	ctx context.Context,
	algorithm Algorithm,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyLocked(ctx); err != nil {
		return err
	}
	return b.supportsLocked(algorithm)
}

func (b *goTPMBackend) CreatePersistent(
	ctx context.Context,
	handle Handle,
	template Template,
	prepare PreparePersistent,
) (result Public, resultErr error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyLocked(ctx); err != nil {
		return Public{}, err
	}
	if !handle.IsPersistent() {
		return Public{}, fmt.Errorf("TPM handle %#x is not persistent", uint32(handle))
	}
	expectedTemplate, err := SigningTemplate(template.Algorithm)
	if err != nil {
		return Public{}, err
	}
	if template != expectedTemplate {
		return Public{}, errors.New("refuse non-canonical TPM signing template")
	}
	if prepare == nil {
		return Public{}, errors.New("persistent creation preparation callback is required")
	}
	objectAuth, err := b.objectAuthorizationLocked(handle)
	if err != nil {
		return Public{}, err
	}
	defer clear(objectAuth)
	if err := b.supportsLocked(template.Algorithm); err != nil {
		return Public{}, err
	}
	occupied, err := b.persistentHandleOccupiedLocked(handle)
	if err != nil {
		return Public{}, fmt.Errorf("inspect target persistent handle: %w", err)
	}
	if occupied {
		return Public{}, fmt.Errorf("%w: %#x", ErrHandleOccupied, uint32(handle))
	}

	childTemplate, err := goTPMPublicTemplate(template)
	if err != nil {
		return Public{}, err
	}
	primaryAuth := make([]byte, authorizationValueBytes)
	if _, err := rand.Read(primaryAuth); err != nil {
		return Public{}, fmt.Errorf("generate transient parent authorization: %w", err)
	}
	defer clear(primaryAuth)

	ownerName := gotpm.HandleName(gotpm.TPMRHOwner)
	primarySession, closePrimarySession, err := b.boundHMACSessionLocked(
		gotpm.TPMRHOwner,
		ownerName,
		b.ownerAuth,
		gotpm.AESEncryption(gotpm.TPMKeyBits(128), gotpm.EncryptInOut),
	)
	if err != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			fmt.Errorf("start CreatePrimary HMAC session: %w", err),
		)
	}
	primaryCommandAuth := slices.Clone(primaryAuth)
	defer clear(primaryCommandAuth)
	primary, primaryErr := (gotpm.CreatePrimary{
		PrimaryHandle: gotpm.AuthHandle{
			Handle: gotpm.TPMRHOwner,
			Name:   ownerName,
			Auth:   primarySession,
		},
		InSensitive: gotpm.TPM2BSensitiveCreate{
			Sensitive: &gotpm.TPMSSensitiveCreate{
				UserAuth: gotpm.TPM2BAuth{Buffer: primaryCommandAuth},
				Data: gotpm.NewTPMUSensitiveCreate(
					&gotpm.TPM2BSensitiveData{},
				),
			},
		},
		InPublic: gotpm.New2B(gotpm.ECCSRKTemplate),
	}).Execute(b.device)
	primarySessionErr := closeSessionError(
		"CreatePrimary",
		closePrimarySession(),
	)
	if primaryErr != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			errors.Join(
				fmt.Errorf("create transient TPM storage primary: %w", primaryErr),
				primarySessionErr,
			),
		)
	}
	if primary == nil {
		return Public{}, errors.Join(
			errors.New("CreatePrimary returned a nil response"),
			primarySessionErr,
		)
	}
	defer func() {
		resultErr = errors.Join(
			resultErr,
			b.flushLocked("transient storage primary", primary.ObjectHandle),
		)
	}()
	if primarySessionErr != nil {
		return Public{}, primarySessionErr
	}

	createSession, closeCreateSession, err := b.boundHMACSessionLocked(
		primary.ObjectHandle,
		primary.Name,
		primaryAuth,
		gotpm.AESEncryption(gotpm.TPMKeyBits(128), gotpm.EncryptInOut),
	)
	if err != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			fmt.Errorf("start Create HMAC session: %w", err),
		)
	}
	createCommandAuth := slices.Clone(objectAuth)
	defer clear(createCommandAuth)
	created, createErr := (gotpm.Create{
		ParentHandle: gotpm.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   createSession,
		},
		InSensitive: gotpm.TPM2BSensitiveCreate{
			Sensitive: &gotpm.TPMSSensitiveCreate{
				UserAuth: gotpm.TPM2BAuth{Buffer: createCommandAuth},
				Data: gotpm.NewTPMUSensitiveCreate(
					&gotpm.TPM2BSensitiveData{},
				),
			},
		},
		InPublic: gotpm.New2B(childTemplate),
	}).Execute(b.device)
	createSessionErr := closeSessionError("Create", closeCreateSession())
	if createErr != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			errors.Join(createErr, createSessionErr),
		)
	}
	if created == nil {
		return Public{}, errors.Join(
			errors.New("Create returned a nil response"),
			createSessionErr,
		)
	}
	defer clear(created.OutPrivate.Buffer)
	if createSessionErr != nil {
		return Public{}, createSessionErr
	}

	loadSession, closeLoadSession, err := b.boundHMACSessionLocked(
		primary.ObjectHandle,
		primary.Name,
		primaryAuth,
		gotpm.AESEncryption(gotpm.TPMKeyBits(128), gotpm.EncryptInOut),
	)
	if err != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			fmt.Errorf("start Load HMAC session: %w", err),
		)
	}
	loaded, loadErr := (gotpm.Load{
		ParentHandle: gotpm.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
			Auth:   loadSession,
		},
		InPrivate: created.OutPrivate,
		InPublic:  created.OutPublic,
	}).Execute(b.device)
	loadSessionErr := closeSessionError("Load", closeLoadSession())
	if loadErr != nil {
		return Public{}, b.mapCreateError(
			template.Algorithm,
			errors.Join(
				fmt.Errorf("load newly created TPM signing key: %w", loadErr),
				loadSessionErr,
			),
		)
	}
	if loaded == nil {
		return Public{}, errors.Join(
			errors.New("Load returned a nil response"),
			loadSessionErr,
		)
	}
	defer func() {
		resultErr = errors.Join(
			resultErr,
			b.flushLocked("transient signing object", loaded.ObjectHandle),
		)
	}()
	if loadSessionErr != nil {
		return Public{}, loadSessionErr
	}

	createdPublicArea, err := created.OutPublic.Contents()
	if err != nil {
		return Public{}, fmt.Errorf("decode created TPM public area: %w", err)
	}
	createdPublic, err := convertGoTPMPublic(
		handle,
		loaded.Name.Buffer,
		createdPublicArea,
	)
	if err != nil {
		return Public{}, fmt.Errorf("validate created TPM public area: %w", err)
	}
	if createdPublic.Template != template {
		return Public{}, errors.New("created TPM public template differs from request")
	}
	if err := prepare(createdPublic); err != nil {
		return Public{}, fmt.Errorf("prepare persistent TPM metadata: %w", err)
	}

	evictSession, closeEvictSession, err := b.boundHMACSessionLocked(
		gotpm.TPMRHOwner,
		ownerName,
		b.ownerAuth,
	)
	if err != nil {
		return Public{}, fmt.Errorf("start EvictControl HMAC session: %w", err)
	}
	_, evictErr := (gotpm.EvictControl{
		Auth: gotpm.AuthHandle{
			Handle: gotpm.TPMRHOwner,
			Name:   ownerName,
			Auth:   evictSession,
		},
		ObjectHandle: &gotpm.NamedHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
		},
		PersistentHandle: gotpm.TPMHandle(handle),
	}).Execute(b.device)
	evictSessionErr := closeSessionError(
		"EvictControl",
		closeEvictSession(),
	)
	if evictErr != nil {
		probed, probeErr := b.readPublicLocked(handle)
		if probeErr == nil && samePublic(createdPublic, probed) {
			if evictSessionErr == nil {
				return probed, nil
			}
			return Public{}, errors.Join(
				fmt.Errorf(
					"persisted TPM signing key at %#x but command-session cleanup failed",
					uint32(handle),
				),
				evictErr,
				evictSessionErr,
			)
		}
		if isOccupiedTPMError(evictErr) {
			return Public{}, errors.Join(
				fmt.Errorf(
					"%w: %#x: %v",
					ErrHandleOccupied,
					uint32(handle),
					evictErr,
				),
				evictSessionErr,
				probeErr,
			)
		}
		return Public{}, errors.Join(
			fmt.Errorf("persist TPM signing key at %#x: %w", uint32(handle), evictErr),
			evictSessionErr,
			probeErr,
		)
	}
	if evictSessionErr != nil {
		return Public{}, evictSessionErr
	}

	persisted, err := b.readPublicLocked(handle)
	if err != nil {
		cleanupErr := b.evictKnownLocked(ObjectReference{
			Handle:   handle,
			Name:     slices.Clone(createdPublic.Name),
			Template: template,
		})
		return Public{}, errors.Join(
			fmt.Errorf("verify newly persisted TPM key: %w", err),
			cleanupErr,
		)
	}
	if !samePublic(createdPublic, persisted) {
		cleanupErr := b.evictKnownLocked(ObjectReference{
			Handle:   handle,
			Name:     slices.Clone(createdPublic.Name),
			Template: template,
		})
		return Public{}, errors.Join(
			errors.New("newly persisted TPM public object changed"),
			cleanupErr,
		)
	}
	return persisted, nil
}

func (b *goTPMBackend) ReadPublic(
	ctx context.Context,
	handle Handle,
) (Public, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyLocked(ctx); err != nil {
		return Public{}, err
	}
	return b.readPublicLocked(handle)
}

func (b *goTPMBackend) Sign(
	ctx context.Context,
	request SignRequest,
) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyLocked(ctx); err != nil {
		return nil, err
	}
	if request.Purpose != SignPurposeCertificate {
		return nil, errors.New("TPM signing purpose is not allowlisted")
	}
	if request.Hash != crypto.SHA256 || len(request.Payload) != crypto.SHA256.Size() {
		return nil, errors.New("typed TPM adapter signs only exact SHA-256 certificate digests")
	}
	public, err := b.readPublicLocked(request.Object.Handle)
	if err != nil {
		return nil, err
	}
	if !matchesReference(public, request.Object) {
		return nil, errors.New("TPM signing object no longer matches expected name or template")
	}
	if request.Scheme != public.Template.SigningScheme {
		return nil, errors.New("TPM signing scheme differs from persistent template")
	}
	objectAuth, err := b.objectAuthorizationLocked(request.Object.Handle)
	if err != nil {
		return nil, err
	}
	defer clear(objectAuth)

	scheme, err := goTPMSignatureScheme(public.Template)
	if err != nil {
		return nil, err
	}
	name := gotpm.TPM2BName{Buffer: slices.Clone(request.Object.Name)}
	signSession, closeSignSession, err := b.boundHMACSessionLocked(
		gotpm.TPMHandle(request.Object.Handle),
		name,
		objectAuth,
		gotpm.AESEncryption(gotpm.TPMKeyBits(128), gotpm.EncryptIn),
	)
	if err != nil {
		return nil, fmt.Errorf("start Sign HMAC session: %w", err)
	}
	response, signErr := (gotpm.Sign{
		KeyHandle: gotpm.AuthHandle{
			Handle: gotpm.TPMHandle(request.Object.Handle),
			Name:   name,
			Auth:   signSession,
		},
		Digest: gotpm.TPM2BDigest{Buffer: slices.Clone(request.Payload)},
		InScheme: scheme,
		Validation: gotpm.TPMTTKHashCheck{
			Tag:       gotpm.TPMSTHashCheck,
			Hierarchy: gotpm.TPMRHNull,
		},
	}).Execute(b.device)
	signSessionErr := closeSessionError("Sign", closeSignSession())
	if signErr != nil {
		return nil, errors.Join(
			fmt.Errorf("TPM certificate sign: %w", signErr),
			signSessionErr,
		)
	}
	if response == nil {
		return nil, errors.Join(
			errors.New("TPM Sign returned a nil response"),
			signSessionErr,
		)
	}
	if signSessionErr != nil {
		return nil, signSessionErr
	}
	return signatureBytes(public.Template, response.Signature)
}

func (b *goTPMBackend) EvictPersistent(
	ctx context.Context,
	reference ObjectReference,
) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.readyLocked(ctx); err != nil {
		return err
	}
	return b.evictKnownLocked(reference)
}

func (b *goTPMBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	clear(b.ownerAuth)
	for handle, auth := range b.objectAuthByHandle {
		clear(auth)
		delete(b.objectAuthByHandle, handle)
	}
	err := b.device.Close()
	b.device = nil
	return err
}

func (b *goTPMBackend) readyLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.closed || b.device == nil {
		return errors.New("TPM backend is closed")
	}
	return nil
}

func (b *goTPMBackend) objectAuthorizationLocked(handle Handle) ([]byte, error) {
	if err := b.requireObjectAuthorizationLocked(handle); err != nil {
		return nil, err
	}
	return slices.Clone(b.objectAuthByHandle[handle]), nil
}

func (b *goTPMBackend) requireObjectAuthorizationLocked(handle Handle) error {
	auth, exists := b.objectAuthByHandle[handle]
	if !exists || len(auth) == 0 {
		return fmt.Errorf(
			"%w: no authorization is configured for handle %#x",
			ErrAuthorizationUnavailable,
			uint32(handle),
		)
	}
	return nil
}

func (b *goTPMBackend) boundHMACSessionLocked(
	handle gotpm.TPMHandle,
	name gotpm.TPM2BName,
	auth []byte,
	extraOptions ...gotpm.AuthOption,
) (gotpm.Session, func() error, error) {
	options := []gotpm.AuthOption{
		gotpm.Auth(auth),
		gotpm.Bound(gotpm.TPMIDHEntity(handle), name, auth),
	}
	options = append(options, extraOptions...)
	return gotpm.HMACSession(
		b.device,
		gotpm.TPMAlgSHA256,
		sha256.Size,
		options...,
	)
}

func (b *goTPMBackend) supportsLocked(algorithm Algorithm) error {
	if algorithm == AlgorithmEd25519 {
		return &UnsupportedCapabilityError{
			Algorithm: algorithm,
			Reason: "go-tpm v0.9.8 has no typed EdDSA public/signature union; refusing fallback",
		}
	}
	if err := b.testParmsLocked(
		algorithm,
		gotpm.ECCSRKTemplate,
		"required ECC P-256 storage parent",
	); err != nil {
		return err
	}
	template, err := SigningTemplate(algorithm)
	if err != nil {
		return err
	}
	public, err := goTPMPublicTemplate(template)
	if err != nil {
		return err
	}
	return b.testParmsLocked(algorithm, public, "requested signing key")
}

func (b *goTPMBackend) testParmsLocked(
	algorithm Algorithm,
	public gotpm.TPMTPublic,
	description string,
) error {
	_, err := (gotpm.TestParms{
		Parameters: gotpm.TPMTPublicParms{
			Type:       public.Type,
			Parameters: public.Parameters,
		},
	}).Execute(b.device)
	if err != nil {
		if isUnsupportedTPMError(err) {
			return &UnsupportedCapabilityError{
				Algorithm: algorithm,
				Reason:    description + ": " + err.Error(),
			}
		}
		return fmt.Errorf(
			"test %s TPM parameters for %s: %w",
			description,
			algorithm,
			err,
		)
	}
	return nil
}

func (b *goTPMBackend) persistentHandleOccupiedLocked(
	handle Handle,
) (bool, error) {
	if !handle.IsPersistent() {
		return false, fmt.Errorf(
			"TPM handle %#x is not owner-persistent",
			uint32(handle),
		)
	}
	_, err := (gotpm.ReadPublic{
		ObjectHandle: gotpm.TPMHandle(handle),
	}).Execute(b.device)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gotpm.TPMRCHandle) ||
		errors.Is(err, gotpm.TPMRCReferenceH0) {
		return false, nil
	}
	return false, fmt.Errorf(
		"probe TPM public handle %#x: %w",
		uint32(handle),
		err,
	)
}

func (b *goTPMBackend) readPublicLocked(handle Handle) (Public, error) {
	if !handle.IsPersistent() {
		return Public{}, fmt.Errorf("TPM handle %#x is not persistent", uint32(handle))
	}
	response, err := (gotpm.ReadPublic{
		ObjectHandle: gotpm.TPMHandle(handle),
	}).Execute(b.device)
	if err != nil {
		if errors.Is(err, gotpm.TPMRCHandle) ||
			errors.Is(err, gotpm.TPMRCReferenceH0) {
			return Public{}, fmt.Errorf("%w: %#x", ErrHandleNotFound, uint32(handle))
		}
		return Public{}, fmt.Errorf("read TPM public handle %#x: %w", uint32(handle), err)
	}
	publicArea, err := response.OutPublic.Contents()
	if err != nil {
		return Public{}, fmt.Errorf("decode TPM public handle %#x: %w", uint32(handle), err)
	}
	return convertGoTPMPublic(handle, response.Name.Buffer, publicArea)
}

func (b *goTPMBackend) evictKnownLocked(reference ObjectReference) error {
	if err := b.requireObjectAuthorizationLocked(reference.Handle); err != nil {
		return err
	}
	public, err := b.readPublicLocked(reference.Handle)
	if err != nil {
		return err
	}
	if !matchesReference(public, reference) {
		return errors.New("refuse to evict TPM object with mismatched name or template")
	}
	ownerName := gotpm.HandleName(gotpm.TPMRHOwner)
	evictSession, closeEvictSession, err := b.boundHMACSessionLocked(
		gotpm.TPMRHOwner,
		ownerName,
		b.ownerAuth,
	)
	if err != nil {
		return fmt.Errorf("start EvictControl HMAC session: %w", err)
	}
	_, evictErr := (gotpm.EvictControl{
		Auth: gotpm.AuthHandle{
			Handle: gotpm.TPMRHOwner,
			Name:   ownerName,
			Auth:   evictSession,
		},
		ObjectHandle: &gotpm.NamedHandle{
			Handle: gotpm.TPMHandle(reference.Handle),
			Name: gotpm.TPM2BName{
				Buffer: slices.Clone(reference.Name),
			},
		},
		PersistentHandle: gotpm.TPMHandle(reference.Handle),
	}).Execute(b.device)
	evictSessionErr := closeSessionError(
		"EvictControl",
		closeEvictSession(),
	)
	if evictErr != nil {
		probed, probeErr := b.readPublicLocked(reference.Handle)
		if errors.Is(probeErr, ErrHandleNotFound) && evictSessionErr == nil {
			return nil
		}
		if probeErr == nil && !matchesReference(probed, reference) {
			probeErr = errors.New(
				"persistent handle changed identity after indeterminate eviction",
			)
		}
		return errors.Join(
			fmt.Errorf(
				"evict persistent TPM handle %#x: %w",
				uint32(reference.Handle),
				evictErr,
			),
			evictSessionErr,
			probeErr,
		)
	}
	if evictSessionErr != nil {
		return evictSessionErr
	}
	if _, err := b.readPublicLocked(reference.Handle); !errors.Is(err, ErrHandleNotFound) {
		if err == nil {
			return errors.New("TPM handle remains present after eviction")
		}
		return fmt.Errorf("verify TPM handle eviction: %w", err)
	}
	return nil
}

func (b *goTPMBackend) flushLocked(
	description string,
	handle gotpm.TPMHandle,
) error {
	if _, err := (gotpm.FlushContext{
		FlushHandle: handle,
	}).Execute(b.device); err != nil {
		return fmt.Errorf("flush %s %#x: %w", description, uint32(handle), err)
	}
	return nil
}

func (b *goTPMBackend) mapCreateError(_ Algorithm, err error) error {
	return fmt.Errorf("create TPM signing key: %w", err)
}

func goTPMPublicTemplate(template Template) (gotpm.TPMTPublic, error) {
	attributes := gotpm.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		SignEncrypt:         true,
	}
	switch template.Algorithm {
	case AlgorithmRSA4096:
		return gotpm.TPMTPublic{
			Type:             gotpm.TPMAlgRSA,
			NameAlg:          gotpm.TPMAlgSHA256,
			ObjectAttributes: attributes,
			Parameters: gotpm.NewTPMUPublicParms(
				gotpm.TPMAlgRSA,
				&gotpm.TPMSRSAParms{
					Symmetric: gotpm.TPMTSymDefObject{Algorithm: gotpm.TPMAlgNull},
					Scheme: gotpm.TPMTRSAScheme{
						Scheme: gotpm.TPMAlgRSASSA,
						Details: gotpm.NewTPMUAsymScheme(
							gotpm.TPMAlgRSASSA,
							&gotpm.TPMSSigSchemeRSASSA{
								HashAlg: gotpm.TPMAlgSHA256,
							},
						),
					},
					KeyBits: 4096,
					Exponent: 65537,
				},
			),
			Unique: gotpm.NewTPMUPublicID(
				gotpm.TPMAlgRSA,
				&gotpm.TPM2BPublicKeyRSA{},
			),
		}, nil
	case AlgorithmECDSAP256:
		return gotpm.TPMTPublic{
			Type:             gotpm.TPMAlgECC,
			NameAlg:          gotpm.TPMAlgSHA256,
			ObjectAttributes: attributes,
			Parameters: gotpm.NewTPMUPublicParms(
				gotpm.TPMAlgECC,
				&gotpm.TPMSECCParms{
					Symmetric: gotpm.TPMTSymDefObject{Algorithm: gotpm.TPMAlgNull},
					Scheme: gotpm.TPMTECCScheme{
						Scheme: gotpm.TPMAlgECDSA,
						Details: gotpm.NewTPMUAsymScheme(
							gotpm.TPMAlgECDSA,
							&gotpm.TPMSSigSchemeECDSA{
								HashAlg: gotpm.TPMAlgSHA256,
							},
						),
					},
					CurveID: gotpm.TPMECCNistP256,
					KDF:     gotpm.TPMTKDFScheme{Scheme: gotpm.TPMAlgNull},
				},
			),
			Unique: gotpm.NewTPMUPublicID(
				gotpm.TPMAlgECC,
				&gotpm.TPMSECCPoint{
					X: gotpm.TPM2BECCParameter{},
					Y: gotpm.TPM2BECCParameter{},
				},
			),
		}, nil
	case AlgorithmEd25519:
		return gotpm.TPMTPublic{}, &UnsupportedCapabilityError{
			Algorithm: template.Algorithm,
			Reason: "go-tpm v0.9.8 has no typed EdDSA public/signature union",
		}
	default:
		return gotpm.TPMTPublic{}, &UnsupportedCapabilityError{
			Algorithm: template.Algorithm,
			Reason:    "unknown key algorithm",
		}
	}
}

func convertGoTPMPublic(
	handle Handle,
	name []byte,
	publicArea *gotpm.TPMTPublic,
) (Public, error) {
	if publicArea == nil {
		return Public{}, errors.New("TPM public area is nil")
	}
	recomputedName, err := gotpm.ObjectName(publicArea)
	if err != nil {
		return Public{}, fmt.Errorf("recompute TPM public name: %w", err)
	}
	if !bytes.Equal(name, recomputedName.Buffer) {
		return Public{}, errors.New("TPM-reported public name does not match public area")
	}

	var algorithm Algorithm
	switch publicArea.Type {
	case gotpm.TPMAlgRSA:
		algorithm = AlgorithmRSA4096
	case gotpm.TPMAlgECC:
		algorithm = AlgorithmECDSAP256
	default:
		return Public{}, &UnsupportedCapabilityError{
			Reason: fmt.Sprintf("TPM public type %#x is not allowlisted", publicArea.Type),
		}
	}
	template, err := SigningTemplate(algorithm)
	if err != nil {
		return Public{}, err
	}
	expected, err := goTPMPublicTemplate(template)
	if err != nil {
		return Public{}, err
	}
	if publicArea.NameAlg != expected.NameAlg ||
		publicArea.ObjectAttributes != expected.ObjectAttributes ||
		len(publicArea.AuthPolicy.Buffer) != 0 ||
		!bytes.Equal(
			marshalPublicParameters(publicArea),
			marshalPublicParameters(&expected),
		) {
		return Public{}, errors.New("TPM public area does not match canonical signing template")
	}
	publicKey, err := gotpm.Pub(*publicArea)
	if err != nil {
		return Public{}, fmt.Errorf("convert TPM public key: %w", err)
	}
	public := Public{
		Handle:    handle,
		Name:      slices.Clone(name),
		Template:  template,
		PublicKey: publicKey,
	}
	if _, err := CanonicalPublicKey(public); err != nil {
		return Public{}, err
	}
	return public, nil
}

func marshalPublicParameters(publicArea *gotpm.TPMTPublic) []byte {
	parameters := gotpm.TPMTPublicParms{
		Type:       publicArea.Type,
		Parameters: publicArea.Parameters,
	}
	return gotpm.Marshal(&parameters)
}

func goTPMSignatureScheme(template Template) (gotpm.TPMTSigScheme, error) {
	switch template.SigningScheme {
	case SchemeRSASSASHA256:
		return gotpm.TPMTSigScheme{
			Scheme: gotpm.TPMAlgRSASSA,
			Details: gotpm.NewTPMUSigScheme(
				gotpm.TPMAlgRSASSA,
				&gotpm.TPMSSchemeHash{HashAlg: gotpm.TPMAlgSHA256},
			),
		}, nil
	case SchemeECDSASHA256:
		return gotpm.TPMTSigScheme{
			Scheme: gotpm.TPMAlgECDSA,
			Details: gotpm.NewTPMUSigScheme(
				gotpm.TPMAlgECDSA,
				&gotpm.TPMSSchemeHash{HashAlg: gotpm.TPMAlgSHA256},
			),
		}, nil
	case SchemeEd25519:
		return gotpm.TPMTSigScheme{}, &UnsupportedCapabilityError{
			Algorithm: AlgorithmEd25519,
			Reason:    "go-tpm v0.9.8 has no typed EdDSA signature union",
		}
	default:
		return gotpm.TPMTSigScheme{}, errors.New("unknown TPM signature scheme")
	}
}

func signatureBytes(template Template, signature gotpm.TPMTSignature) ([]byte, error) {
	switch template.SigningScheme {
	case SchemeRSASSASHA256:
		if signature.SigAlg != gotpm.TPMAlgRSASSA {
			return nil, errors.New("TPM returned a non-RSASSA signature")
		}
		value, err := signature.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("decode TPM RSASSA signature: %w", err)
		}
		if value.Hash != gotpm.TPMAlgSHA256 || len(value.Sig.Buffer) != 512 {
			return nil, errors.New("TPM returned unexpected RSA-4096 signature parameters")
		}
		return slices.Clone(value.Sig.Buffer), nil
	case SchemeECDSASHA256:
		if signature.SigAlg != gotpm.TPMAlgECDSA {
			return nil, errors.New("TPM returned a non-ECDSA signature")
		}
		value, err := signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("decode TPM ECDSA signature: %w", err)
		}
		if value.Hash != gotpm.TPMAlgSHA256 {
			return nil, errors.New("TPM returned unexpected ECDSA hash")
		}
		r := new(big.Int).SetBytes(value.SignatureR.Buffer)
		s := new(big.Int).SetBytes(value.SignatureS.Buffer)
		order := elliptic.P256().Params().N
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
			return nil, errors.New("TPM returned out-of-range ECDSA signature values")
		}
		encoded, err := asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("encode TPM ECDSA signature: %w", err)
		}
		return encoded, nil
	default:
		return nil, &UnsupportedCapabilityError{
			Algorithm: template.Algorithm,
			Reason:    "typed TPM signature conversion is unavailable",
		}
	}
}

func matchesReference(public Public, reference ObjectReference) bool {
	return public.Handle == reference.Handle &&
		public.Template == reference.Template &&
		bytes.Equal(public.Name, reference.Name)
}

func samePublic(left Public, right Public) bool {
	if !matchesReference(left, ObjectReference{
		Handle:   right.Handle,
		Name:     right.Name,
		Template: right.Template,
	}) {
		return false
	}
	leftDER, leftErr := CanonicalPublicKey(left)
	rightDER, rightErr := CanonicalPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

func isUnsupportedTPMError(err error) bool {
	for _, responseCode := range []gotpm.TPMRC{
		gotpm.TPMRCAsymmetric,
		gotpm.TPMRCAttributes,
		gotpm.TPMRCCurve,
		gotpm.TPMRCHash,
		gotpm.TPMRCKeySize,
		gotpm.TPMRCSymmetric,
		gotpm.TPMRCMode,
		gotpm.TPMRCKDF,
		gotpm.TPMRCCommandCode,
		gotpm.TPMRCScheme,
		gotpm.TPMRCType,
		gotpm.TPMRCValue,
	} {
		if errors.Is(err, responseCode) {
			return true
		}
	}
	return false
}

func isOccupiedTPMError(err error) bool {
	return errors.Is(err, gotpm.TPMRCNVDefined)
}

func validateAuthorizationValue(label string, auth []byte) error {
	if len(auth) != authorizationValueBytes {
		return fmt.Errorf(
			"%w: %s authorization must be exactly %d bytes",
			ErrAuthorizationUnavailable,
			label,
			authorizationValueBytes,
		)
	}
	nonzero := byte(0)
	for _, value := range auth {
		nonzero |= value
	}
	if nonzero == 0 {
		return fmt.Errorf(
			"%w: %s authorization cannot be all zero",
			ErrAuthorizationUnavailable,
			label,
		)
	}
	return nil
}

func closeSessionError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close %s HMAC session: %w", operation, err)
}

var _ Backend = (*goTPMBackend)(nil)
