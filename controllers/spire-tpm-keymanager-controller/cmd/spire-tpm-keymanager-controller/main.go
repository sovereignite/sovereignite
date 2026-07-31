package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/sovereignite/sovereignite/controllers/internal/kubeapi"
)

const keyManagersPath = "/apis/spire.sovereignite.io/v1alpha1/spiretpmkeymanagers"

func main() {
	var pollInterval time.Duration
	var once bool
	var leaderElectionNamespace string
	flag.DurationVar(&pollInterval, "poll-interval", 30*time.Second, "poll interval")
	flag.BoolVar(&once, "once", false, "run one reconciliation pass")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "accepted for manifest compatibility")
	flag.Parse()
	_ = leaderElectionNamespace

	client, err := kubeapi.NewInCluster()
	if err != nil {
		log.Fatal(err)
	}

	for {
		if err := reconcile(client); err != nil {
			log.Printf("reconcile failed: %v", err)
		}
		if once {
			return
		}
		time.Sleep(pollInterval)
	}
}

func reconcile(client *kubeapi.Client) error {
	items, err := client.List(keyManagersPath)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := reconcileOne(client, item); err != nil {
			log.Printf("SPIRETPMKeyManager %s/%s invalid: %v", kubeapi.Namespace(item), kubeapi.Name(item), err)
		}
	}
	return nil
}

func reconcileOne(client *kubeapi.Client, obj map[string]any) error {
	spec := kubeapi.NestedMap(obj, "spec")
	socketPath := kubeapi.StringValue(spec["socketPath"])
	pkcs11 := kubeapi.Map(spec["pkcs11"])
	keys := kubeapi.Map(spec["keys"])
	if socketPath == "" {
		return patch(client, obj, "False", "InvalidSpec", "spec.socketPath is required", "")
	}
	if kubeapi.StringValue(pkcs11["modulePath"]) == "" || kubeapi.StringValue(pkcs11["tokenLabel"]) == "" {
		return patch(client, obj, "False", "InvalidSpec", "spec.pkcs11.modulePath and tokenLabel are required", "")
	}
	active := kubeapi.StringValue(keys["serverCA"])
	if active == "" {
		return patch(client, obj, "False", "InvalidSpec", "spec.keys.serverCA is required", "")
	}
	return patch(client, obj, "True", "Ready", fmt.Sprintf("SPIRE KeyManager configured at %s", socketPath), active)
}

func patch(client *kubeapi.Client, obj map[string]any, status, reason, message, activeKeyLabel string) error {
	statusObj := map[string]any{
		"observedGeneration": kubeapi.Generation(obj),
		"conditions": []map[string]any{
			kubeapi.ReadyCondition(status, reason, message),
		},
	}
	if activeKeyLabel != "" {
		statusObj["activeKeyLabel"] = activeKeyLabel
	}
	ns := kubeapi.Namespace(obj)
	name := kubeapi.Name(obj)
	return client.MergePatch("/apis/spire.sovereignite.io/v1alpha1/namespaces/"+ns+"/spiretpmkeymanagers/"+name+"/status", map[string]any{
		"status": statusObj,
	})
}
