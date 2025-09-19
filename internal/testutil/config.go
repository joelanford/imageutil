package testutil

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/pkg/sysregistriesv2"
)

func CreateCertDir(t testing.TB, cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.crt")
	writeCertToFile(t, certFile, cert)

	return tmpDir
}

func CreatePerHostCertDir(t testing.TB, baseDir string, host string, cert *x509.Certificate) {
	certDir := filepath.Join(baseDir, host)
	require.NoError(t, os.MkdirAll(certDir, 0700))

	certFile := filepath.Join(certDir, "cert.crt")
	writeCertToFile(t, certFile, cert)
}

func writeCertToFile(t testing.TB, path string, cert *x509.Certificate) {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	require.NoError(t, os.WriteFile(path, data, 0644), "failed to write certificate")
}

func CreateRegistriesConf(t testing.TB, conf sysregistriesv2.V2RegistriesConf) string {
	tmpDir := t.TempDir()
	confPath := filepath.Join(tmpDir, "registries.conf")

	tomlData, err := toml.Marshal(conf)
	require.NoError(t, err, "failed to marshal registries.conf")
	require.NoError(t, os.WriteFile(confPath, tomlData, 0644), "failed to write registries.conf")

	return confPath
}

type AuthConfig struct {
	Auth          string `json:"auth,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
}

type AuthFile struct {
	AuthConfigs map[string]AuthConfig `json:"auths"`
	CredHelpers map[string]string     `json:"credHelpers,omitempty"`
}

func CreateAuthFile(t testing.TB, authFile AuthFile) string {
	tmpDir := t.TempDir()
	authPath := filepath.Join(tmpDir, "auth.json")

	authBytes, err := json.Marshal(authFile)
	require.NoError(t, err, "failed to marshal auth.json")

	err = os.WriteFile(authPath, authBytes, 0644)
	require.NoError(t, err, "failed to write auth.json")

	return authPath
}
