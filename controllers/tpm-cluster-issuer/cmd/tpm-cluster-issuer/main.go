package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sovereignite/sovereignite/controllers/internal/kubeapi"
	"github.com/sovereignite/sovereignite/controllers/internal/signing"
)

const (
	issuersPath             = "/apis/pki.sovereignite.io/v1alpha1/tpmclusterissuers"
	certificateRequestsPath = "/apis/cert-manager.io/v1/certificaterequests"
)

type issuer struct {
	Name                     string
	SignerName               string
	CAConfigMapNamespace     string
	CAConfigMapName          string
	CAConfigMapKey           string
	PKCS11                   signing.PKCS11Ref
	Profiles                 map[string]profile
	RequireApprovedCondition bool
	DenyCARequests           bool
	Object                   map[string]any
}

type profile struct {
	MaxDuration               time.Duration
	Usages                    []string
	AllowedDNSDomains         []string
	AllowedSpiffeTrustDomains []string
	AllowWildcardDNSNames     bool
	IsCA                      bool
	MaxPathLen                int
}

func main() {
	var pollInterval time.Duration
	var once bool
	var issuerGroup string
	var issuerKind string
	var defaultProfile string
	var leaderElectionNamespace string
	flag.DurationVar(&pollInterval, "poll-interval", 20*time.Second, "poll interval")
	flag.BoolVar(&once, "once", false, "run one reconciliation pass")
	flag.StringVar(&issuerGroup, "issuer-group", "pki.sovereignite.io", "cert-manager issuerRef group to handle")
	flag.StringVar(&issuerKind, "issuer-kind", "TPMClusterIssuer", "cert-manager issuerRef kind to handle")
	flag.StringVar(&defaultProfile, "default-profile", "default", "issuer profile to use")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "accepted for manifest compatibility")
	flag.Parse()
	_ = leaderElectionNamespace

	client, err := kubeapi.NewInCluster()
	if err != nil {
		log.Fatal(err)
	}

	for {
		if err := reconcile(client, issuerGroup, issuerKind, defaultProfile); err != nil {
			log.Printf("reconcile failed: %v", err)
		}
		if once {
			return
		}
		time.Sleep(pollInterval)
	}
}

func reconcile(client *kubeapi.Client, issuerGroup, issuerKind, defaultProfile string) error {
	requests, err := client.List(certificateRequestsPath)
	if err != nil {
		return err
	}

	issuers := map[string]issuer{}
	for _, cr := range requests {
		if kubeapi.NestedString(cr, "status", "certificate") != "" {
			continue
		}
		ref := kubeapi.NestedMap(cr, "spec", "issuerRef")
		if kubeapi.StringValue(ref["group"]) != issuerGroup || kubeapi.StringValue(ref["kind"]) != issuerKind {
			continue
		}
		issuerName := kubeapi.StringValue(ref["name"])
		if issuerName == "" {
			continue
		}
		iss, ok := issuers[issuerName]
		if !ok {
			loaded, err := loadIssuer(client, issuerName)
			if err != nil {
				log.Printf("issuer %s unavailable: %v", issuerName, err)
				continue
			}
			iss = loaded
			issuers[issuerName] = loaded
		}
		if err := signCertificateRequest(client, iss, cr, defaultProfile); err != nil {
			log.Printf("CertificateRequest %s/%s not signed: %v", kubeapi.Namespace(cr), kubeapi.Name(cr), err)
			continue
		}
		log.Printf("CertificateRequest %s/%s signed by issuer %s", kubeapi.Namespace(cr), kubeapi.Name(cr), issuerName)
	}
	return nil
}

func loadIssuer(client *kubeapi.Client, name string) (issuer, error) {
	obj, err := client.Get(issuersPath + "/" + name)
	if err != nil {
		return issuer{}, err
	}
	iss, err := parseIssuer(client, obj)
	if err != nil {
		patchIssuerReady(client, obj, "False", "InvalidIssuer", err.Error(), "")
		return issuer{}, err
	}
	patchIssuerReady(client, obj, "True", "Ready", "issuer accepted", "")
	return iss, nil
}

func parseIssuer(client *kubeapi.Client, obj map[string]any) (issuer, error) {
	spec := kubeapi.NestedMap(obj, "spec")
	caRef := kubeapi.Map(spec["caRef"])
	caConfigRef := kubeapi.Map(caRef["certificateConfigMapRef"])
	caName := kubeapi.StringValue(caRef["name"])
	caConfigName := kubeapi.StringValue(caConfigRef["name"])
	if caConfigName == "" {
		caConfigName = caName
	}
	caConfigNamespace := kubeapi.StringValue(caConfigRef["namespace"])
	if caConfigNamespace == "" {
		caConfigNamespace = "sovereignite-system"
	}
	caConfigKey := kubeapi.StringValue(caConfigRef["key"])
	if caConfigKey == "" {
		caConfigKey = "ca.crt"
	}

	pkcs11 := kubeapi.Map(spec["pkcs11"])
	pin, err := pinFromSpec(client, pkcs11)
	if err != nil {
		return issuer{}, err
	}

	iss := issuer{
		Name:                 kubeapi.Name(obj),
		SignerName:           kubeapi.StringValue(spec["signerName"]),
		CAConfigMapNamespace: caConfigNamespace,
		CAConfigMapName:      caConfigName,
		CAConfigMapKey:       caConfigKey,
		PKCS11: signing.PKCS11Ref{
			ModulePath: kubeapi.StringValue(pkcs11["modulePath"]),
			TokenLabel: kubeapi.StringValue(pkcs11["tokenLabel"]),
			KeyLabel:   kubeapi.StringValue(pkcs11["keyLabel"]),
			UserPIN:    pin,
		},
		Profiles:                 parseProfiles(kubeapi.Map(spec["profiles"])),
		RequireApprovedCondition: kubeapi.BoolValue(kubeapi.Map(spec["requestPolicy"])["requireApprovedCondition"], true),
		DenyCARequests:           kubeapi.BoolValue(kubeapi.Map(spec["requestPolicy"])["denyCARequests"], true),
		Object:                   obj,
	}
	if iss.SignerName == "" {
		return issuer{}, fmt.Errorf("spec.signerName is required")
	}
	return iss, nil
}

func parseProfiles(raw map[string]any) map[string]profile {
	out := map[string]profile{}
	for name, value := range raw {
		m := kubeapi.Map(value)
		out[name] = profile{
			MaxDuration:               signing.ParseDuration(kubeapi.StringValue(m["maxDuration"])),
			Usages:                    kubeapi.StringSlice(m["usages"]),
			AllowedDNSDomains:         kubeapi.StringSlice(m["allowedDNSDomains"]),
			AllowedSpiffeTrustDomains: kubeapi.StringSlice(m["allowedSpiffeTrustDomains"]),
			AllowWildcardDNSNames:     kubeapi.BoolValue(m["allowWildcardDNSNames"], false),
			IsCA:                      kubeapi.BoolValue(m["isCA"], false),
			MaxPathLen:                int(kubeapi.Int64Value(m["maxPathLen"])),
		}
	}
	if _, ok := out["default"]; !ok {
		out["default"] = profile{MaxDuration: 24 * time.Hour, Usages: []string{"digital signature"}}
	}
	return out
}

func signCertificateRequest(client *kubeapi.Client, iss issuer, cr map[string]any, defaultProfile string) error {
	if kubeapi.HasCondition(cr, "Denied", "True") {
		return fmt.Errorf("request is denied")
	}
	if iss.RequireApprovedCondition && !kubeapi.HasCondition(cr, "Approved", "True") {
		return fmt.Errorf("request is not approved")
	}
	spec := kubeapi.NestedMap(cr, "spec")
	requestedCA := kubeapi.BoolValue(spec["isCA"], false)
	if iss.DenyCARequests && requestedCA {
		return fmt.Errorf("CA certificate requests are denied")
	}

	selectedProfile := iss.Profiles[defaultProfile]
	requestedUsages := kubeapi.StringSlice(spec["usages"])
	if len(requestedUsages) == 0 {
		requestedUsages = selectedProfile.Usages
	}
	if len(selectedProfile.Usages) > 0 && !usageSubset(requestedUsages, selectedProfile.Usages) {
		return fmt.Errorf("requested usages %v exceed profile usages %v", requestedUsages, selectedProfile.Usages)
	}

	request := kubeapi.StringValue(spec["request"])
	if request == "" {
		return fmt.Errorf("spec.request is empty")
	}
	csrBytes, err := base64.StdEncoding.DecodeString(request)
	if err != nil {
		return fmt.Errorf("decode spec.request: %w", err)
	}
	caPEM, err := client.GetConfigMapValue(iss.CAConfigMapNamespace, iss.CAConfigMapName, iss.CAConfigMapKey)
	if err != nil {
		return err
	}

	issued, err := signing.SignCSR(csrBytes, caPEM, iss.PKCS11, signing.Options{
		Usages:                    requestedUsages,
		MaxDuration:               selectedProfile.MaxDuration,
		RequestedDuration:         signing.ParseDuration(kubeapi.StringValue(spec["duration"])),
		AllowedDNSDomains:         selectedProfile.AllowedDNSDomains,
		AllowedSpiffeTrustDomains: selectedProfile.AllowedSpiffeTrustDomains,
		AllowWildcardDNSNames:     selectedProfile.AllowWildcardDNSNames,
		AllowCA:                   requestedCA && !iss.DenyCARequests && selectedProfile.IsCA,
		IsCA:                      requestedCA,
		MaxPathLen:                selectedProfile.MaxPathLen,
	})
	if err != nil {
		return err
	}

	ns := kubeapi.Namespace(cr)
	name := kubeapi.Name(cr)
	cert64 := base64.StdEncoding.EncodeToString([]byte(issued.CertificatePEM))
	ca64 := base64.StdEncoding.EncodeToString([]byte(issued.CAPEM))
	if err := client.MergePatch("/apis/cert-manager.io/v1/namespaces/"+ns+"/certificaterequests/"+name+"/status", map[string]any{
		"status": map[string]any{
			"certificate": cert64,
			"ca":          ca64,
			"conditions": []map[string]any{
				{
					"type":               "Ready",
					"status":             "True",
					"reason":             "Issued",
					"message":            "certificate issued by TPMClusterIssuer",
					"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}); err != nil {
		return err
	}
	patchIssuerReady(client, iss.Object, "True", "Issued", "last issued serial "+issued.Serial, issued.Serial)
	return nil
}

func pinFromSpec(client *kubeapi.Client, pkcs11 map[string]any) (string, error) {
	if envName := kubeapi.StringValue(pkcs11["userPinEnv"]); envName != "" {
		return strings.TrimSpace(os.Getenv(envName)), nil
	}
	ref := kubeapi.Map(pkcs11["userPinSecretRef"])
	name := kubeapi.StringValue(ref["name"])
	namespace := kubeapi.StringValue(ref["namespace"])
	key := kubeapi.StringValue(ref["key"])
	if name == "" {
		return "", nil
	}
	if namespace == "" || key == "" {
		return "", fmt.Errorf("userPinSecretRef requires namespace and key")
	}
	return client.GetSecretValue(namespace, name, key)
}

func patchIssuerReady(client *kubeapi.Client, obj map[string]any, status, reason, message, serial string) {
	name := kubeapi.Name(obj)
	if name == "" {
		return
	}
	st := map[string]any{
		"observedGeneration": kubeapi.Generation(obj),
		"conditions": []map[string]any{
			kubeapi.ReadyCondition(status, reason, message),
		},
	}
	if serial != "" {
		st["lastIssuedSerial"] = serial
	}
	if err := client.MergePatch(issuersPath+"/"+name+"/status", map[string]any{"status": st}); err != nil {
		log.Printf("patch issuer %s status failed: %v", name, err)
	}
}

func usageSubset(requested, allowed []string) bool {
	allowedSet := map[string]struct{}{}
	for _, usage := range allowed {
		allowedSet[normalizeUsage(usage)] = struct{}{}
	}
	for _, usage := range requested {
		if _, ok := allowedSet[normalizeUsage(usage)]; !ok {
			return false
		}
	}
	return true
}

func normalizeUsage(usage string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(usage, "_", " ")))
}
