package signing

import (
	"crypto/x509"
	"testing"
)

func TestUsagesRejectsCAUsagesWhenNotAllowed(t *testing.T) {
	if _, _, err := Usages([]string{"cert sign"}, false); err == nil {
		t.Fatal("expected cert sign usage to be rejected when CA issuance is not allowed")
	}
}

func TestUsagesAllowsCAUsagesWhenAllowed(t *testing.T) {
	keyUsage, _, err := Usages([]string{"cert sign", "crl sign"}, true)
	if err != nil {
		t.Fatalf("expected CA usages to be allowed: %v", err)
	}
	if keyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("expected cert sign key usage")
	}
	if keyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("expected crl sign key usage")
	}
}

func TestUsagesAcceptsCertManagerSigningAlias(t *testing.T) {
	keyUsage, _, err := Usages([]string{"signing"}, false)
	if err != nil {
		t.Fatalf("expected signing alias to be accepted: %v", err)
	}
	if keyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("expected signing alias to map to digital signature")
	}
}
