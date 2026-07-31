package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sovereignite/sovereignite/controllers/internal/kubeapi"
	"github.com/sovereignite/sovereignite/controllers/internal/signing"
)

const (
	policiesPath = "/apis/pki.sovereignite.io/v1alpha1/tpmcsrsignerpolicies"
	csrsPath     = "/apis/certificates.k8s.io/v1/certificatesigningrequests"
)

type policy struct {
	Name                     string
	SignerName               string
	CAConfigMapNamespace     string
	CAConfigMapName          string
	CAConfigMapKey           string
	PKCS11                   signing.PKCS11Ref
	AllowedUsages            []string
	AllowedSubjectRegexes    []*regexp.Regexp
	MaxDuration              time.Duration
	RequireApprovedCondition bool
	Object                   map[string]any
}

func main() {
	var pollInterval time.Duration
	var once bool
	var policyName string
	var leaderElectionNamespace string
	flag.DurationVar(&pollInterval, "poll-interval", 20*time.Second, "poll interval")
	flag.BoolVar(&once, "once", false, "run one reconciliation pass")
	flag.StringVar(&policyName, "policy-name", "", "optional single TPMCSRSignerPolicy name")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "accepted for manifest compatibility")
	flag.Parse()
	_ = leaderElectionNamespace

	client, err := kubeapi.NewInCluster()
	if err != nil {
		log.Fatal(err)
	}

	for {
		if err := reconcile(client, policyName); err != nil {
			log.Printf("reconcile failed: %v", err)
		}
		if once {
			return
		}
		time.Sleep(pollInterval)
	}
}

func reconcile(client *kubeapi.Client, policyName string) error {
	policies, err := loadPolicies(client, policyName)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		log.Printf("no TPM CSR signer policies found")
		return nil
	}

	csrs, err := client.List(csrsPath)
	if err != nil {
		return err
	}
	for _, csrObj := range csrs {
		name := kubeapi.Name(csrObj)
		if kubeapi.NestedString(csrObj, "status", "certificate") != "" {
			continue
		}
		spec := kubeapi.NestedMap(csrObj, "spec")
		signerName := kubeapi.StringValue(spec["signerName"])
		p, ok := policies[signerName]
		if !ok {
			continue
		}
		if err := signCSR(client, p, csrObj); err != nil {
			log.Printf("CSR %s not signed: %v", name, err)
			continue
		}
		log.Printf("CSR %s signed with policy %s", name, p.Name)
	}
	return nil
}

func loadPolicies(client *kubeapi.Client, policyName string) (map[string]policy, error) {
	items, err := client.List(policiesPath)
	if err != nil {
		return nil, err
	}
	out := map[string]policy{}
	for _, item := range items {
		if policyName != "" && kubeapi.Name(item) != policyName {
			continue
		}
		p, err := parsePolicy(client, item)
		if err != nil {
			patchPolicyReady(client, item, "False", "InvalidPolicy", err.Error())
			log.Printf("policy %s invalid: %v", kubeapi.Name(item), err)
			continue
		}
		out[p.SignerName] = p
		patchPolicyReady(client, item, "True", "Ready", "policy accepted")
	}
	return out, nil
}

func parsePolicy(client *kubeapi.Client, obj map[string]any) (policy, error) {
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
		return policy{}, err
	}

	var regexes []*regexp.Regexp
	for _, pattern := range kubeapi.StringSlice(spec["allowedSubjectRegexes"]) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return policy{}, fmt.Errorf("compile subject regex %q: %w", pattern, err)
		}
		regexes = append(regexes, re)
	}

	p := policy{
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
		AllowedUsages:            kubeapi.StringSlice(spec["allowedUsages"]),
		AllowedSubjectRegexes:    regexes,
		MaxDuration:              signing.ParseDuration(kubeapi.StringValue(spec["maxDuration"])),
		RequireApprovedCondition: kubeapi.BoolValue(spec["requireApprovedCondition"], true),
		Object:                   obj,
	}
	if p.SignerName == "" {
		return policy{}, fmt.Errorf("spec.signerName is required")
	}
	if len(p.AllowedUsages) == 0 {
		return policy{}, fmt.Errorf("spec.allowedUsages is required")
	}
	return p, nil
}

func signCSR(client *kubeapi.Client, p policy, csrObj map[string]any) error {
	if kubeapi.HasCondition(csrObj, "Denied", "True") {
		return fmt.Errorf("CSR is denied")
	}
	if p.RequireApprovedCondition && !kubeapi.HasCondition(csrObj, "Approved", "True") {
		return fmt.Errorf("CSR is not approved")
	}

	spec := kubeapi.NestedMap(csrObj, "spec")
	request := kubeapi.StringValue(spec["request"])
	if request == "" {
		return fmt.Errorf("spec.request is empty")
	}
	requestedUsages := kubeapi.StringSlice(spec["usages"])
	if !usageSubset(requestedUsages, p.AllowedUsages) {
		return fmt.Errorf("requested usages %v exceed policy usages %v", requestedUsages, p.AllowedUsages)
	}
	csrBytes, err := base64.StdEncoding.DecodeString(request)
	if err != nil {
		return fmt.Errorf("decode spec.request: %w", err)
	}
	parsedCSR, err := signing.ParseCSR(csrBytes)
	if err != nil {
		return err
	}
	if len(p.AllowedSubjectRegexes) > 0 && !subjectAllowed(parsedCSR.Subject.String(), parsedCSR.Subject.CommonName, p.AllowedSubjectRegexes) {
		return fmt.Errorf("CSR subject %q is outside policy", parsedCSR.Subject.String())
	}

	caPEM, err := client.GetConfigMapValue(p.CAConfigMapNamespace, p.CAConfigMapName, p.CAConfigMapKey)
	if err != nil {
		return err
	}
	duration := time.Duration(kubeapi.Int64Value(spec["expirationSeconds"])) * time.Second
	issued, err := signing.SignCSR(csrBytes, caPEM, p.PKCS11, signing.Options{
		Usages:            requestedUsages,
		MaxDuration:       p.MaxDuration,
		RequestedDuration: duration,
	})
	if err != nil {
		return err
	}

	cert64 := base64.StdEncoding.EncodeToString([]byte(issued.CertificatePEM))
	if err := client.MergePatch(csrsPath+"/"+kubeapi.Name(csrObj)+"/status", map[string]any{
		"status": map[string]any{
			"certificate": cert64,
		},
	}); err != nil {
		return err
	}

	signed := kubeapi.Int64Value(kubeapi.NestedMap(p.Object, "status")["signedRequests"]) + 1
	return client.MergePatch(policiesPath+"/"+p.Name+"/status", map[string]any{
		"status": map[string]any{
			"observedGeneration": kubeapi.Generation(p.Object),
			"signedRequests":     signed,
			"conditions": []map[string]any{
				kubeapi.ReadyCondition("True", "Signed", "last signed serial "+issued.Serial),
			},
		},
	})
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

func patchPolicyReady(client *kubeapi.Client, obj map[string]any, status, reason, message string) {
	name := kubeapi.Name(obj)
	if name == "" {
		return
	}
	if err := client.MergePatch(policiesPath+"/"+name+"/status", map[string]any{
		"status": map[string]any{
			"observedGeneration": kubeapi.Generation(obj),
			"conditions": []map[string]any{
				kubeapi.ReadyCondition(status, reason, message),
			},
		},
	}); err != nil {
		log.Printf("patch policy %s status failed: %v", name, err)
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

func subjectAllowed(fullSubject, commonName string, regexes []*regexp.Regexp) bool {
	for _, re := range regexes {
		if re.MatchString(commonName) || re.MatchString(fullSubject) {
			return true
		}
	}
	return false
}
