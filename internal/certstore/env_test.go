package certstore

import (
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnv(t *testing.T) {
	t.Run("default is noop", func(t *testing.T) {
		st, desc, err := FromEnv(envMap(nil))
		if err != nil || desc != "none" {
			t.Fatalf("desc=%q err=%v", desc, err)
		}
		if _, ok := st.(NoopStore); !ok {
			t.Fatalf("got %T, want NoopStore", st)
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "None"})); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("file", func(t *testing.T) {
		st, desc, err := FromEnv(envMap(map[string]string{EnvStore: "file", EnvStoreDir: "/data/certs"}))
		if err != nil || !strings.HasPrefix(desc, "file:/data/certs") {
			t.Fatalf("desc=%q err=%v", desc, err)
		}
		if _, ok := st.(*FileStore); !ok {
			t.Fatalf("got %T", st)
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "file"})); err == nil {
			t.Fatal("file without dir must fail")
		}
	})
	t.Run("file-sealed", func(t *testing.T) {
		st, desc, err := FromEnv(envMap(map[string]string{
			EnvStore: "file-sealed", EnvStoreDir: "/data", EnvKEKVault: "kv", EnvKEKName: "kek",
		}))
		if err != nil {
			t.Fatal(err)
		}
		ss, ok := st.(*SealedStore)
		if !ok {
			t.Fatalf("got %T", st)
		}
		rel := ss.Releaser.(*SKRReleaser)
		if rel.AKVEndpoint != "https://kv.vault.azure.net" || rel.KID != "kek" || rel.MAAEndpoint != DefaultMAAProvider || rel.URL != "" {
			t.Fatalf("releaser = %+v", rel)
		}
		if !strings.Contains(desc, "kek=https://kv.vault.azure.net/kek") {
			t.Fatalf("desc=%q", desc)
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "file-sealed", EnvStoreDir: "/data", EnvKEKVault: "kv"})); err == nil {
			t.Fatal("missing kek name must fail")
		}
	})
	t.Run("keyvault-sealed", func(t *testing.T) {
		st, desc, err := FromEnv(envMap(map[string]string{
			EnvStore: "keyvault-sealed", EnvKEKVault: "https://hsm.managedhsm.azure.net", EnvKEKName: "kek",
			EnvSecretVault: "secrets-kv", EnvMAAProvider: "maa.example", EnvSKRURL: "http://localhost:9999/key/release",
			"IDENTITY_ENDPOINT": "http://localhost:42/msi/token", "IDENTITY_HEADER": "h", EnvMSIClientID: "cid",
		}))
		if err != nil {
			t.Fatal(err)
		}
		ss := st.(*SealedStore)
		kv := ss.Blobs.(*KeyVaultSecretStore)
		if kv.VaultURL != "https://secrets-kv.vault.azure.net" || kv.SecretName != DefaultSecretName {
			t.Fatalf("kv = %+v", kv)
		}
		ms := kv.Tokens.(*MSITokenSource)
		if ms.Endpoint != "http://localhost:42/msi/token" || ms.Header != "h" || ms.ClientID != "cid" {
			t.Fatalf("msi = %+v", ms)
		}
		rel := ss.Releaser.(*SKRReleaser)
		if rel.MAAEndpoint != "maa.example" || rel.URL != "http://localhost:9999/key/release" || rel.AKVEndpoint != "https://hsm.managedhsm.azure.net" {
			t.Fatalf("releaser = %+v", rel)
		}
		if !strings.Contains(desc, "keyvault-sealed:https://secrets-kv.vault.azure.net/secrets/"+DefaultSecretName) {
			t.Fatalf("desc=%q", desc)
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "keyvault-sealed", EnvKEKVault: "kv", EnvKEKName: "kek"})); err == nil {
			t.Fatal("missing secret vault must fail")
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "s3"})); err == nil {
			t.Fatal("unknown mode must fail")
		}
	})
}
