package testutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/olareg/olareg"
	"github.com/olareg/olareg/config"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	orasremote "oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

type TestRegistry struct {
	registry *olareg.Server
	server   *httptest.Server
	url      url.URL
}

func (t *TestRegistry) SetRegistry(registry *olareg.Server) {
	t.registry = registry
}

func (t *TestRegistry) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if t.registry == nil {
		resp.WriteHeader(http.StatusNotFound)
		return
	}
	t.registry.ServeHTTP(resp, req)
}

func (t *TestRegistry) Close() {
	t.server.Close()
}

func (t *TestRegistry) Certificate() *x509.Certificate {
	return t.server.Certificate()
}

func (t *TestRegistry) URL() url.URL {
	return t.url
}

func (t *TestRegistry) Host() string {
	return t.url.Host
}

func SetupHTTPRegistry(t testing.TB) *TestRegistry {
	reg, err := setupRegistry(httptest.NewServer)
	require.NoError(t, err)
	return reg
}

func SetupHTTPSRegistry(t testing.TB) *TestRegistry {
	reg, err := setupRegistry(httptest.NewTLSServer)
	require.NoError(t, err)
	return reg
}

type RegistryClientOption func(repo *orasremote.Repository)

func WithCredential(cred auth.Credential) RegistryClientOption {
	return func(repo *orasremote.Repository) {
		repo.Client.(*auth.Client).Credential = func(_ context.Context, _ string) (auth.Credential, error) {
			return cred, nil
		}
	}
}

func WithHTTPClient(useHTTP bool) RegistryClientOption {
	return func(repo *orasremote.Repository) {
		repo.PlainHTTP = useHTTP
	}
}

func WithInsecureSkipVerify(insecureSkipVerify bool) RegistryClientOption {
	return func(repo *orasremote.Repository) {
		tlsClientConfig(repo).InsecureSkipVerify = insecureSkipVerify
	}
}

func WithRootCAs(rootCAs *x509.CertPool) RegistryClientOption {
	return func(repo *orasremote.Repository) {
		tlsClientConfig(repo).RootCAs = rootCAs
	}
}

func tlsClientConfig(repo *orasremote.Repository) *tls.Config {
	tlsConfig := repo.Client.(*auth.Client).Client.Transport.(*http.Transport).TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
		repo.Client.(*auth.Client).Client.Transport.(*http.Transport).TLSClientConfig = tlsConfig
	}
	return tlsConfig
}

func PushAndTagManifest(t testing.TB, ref registry.Reference, opts ...RegistryClientOption) {
	repo := newTestRepo(ref, opts...)
	manifest, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{SchemaVersion: 2},
		Config:    ocispec.DescriptorEmptyJSON,
	})
	require.NoError(t, err)

	_, err = oras.PushBytes(t.Context(), repo, ocispec.MediaTypeImageConfig, []byte(`{}`))
	require.NoError(t, err)

	desc, err := oras.PushBytes(t.Context(), repo, ocispec.MediaTypeImageManifest, manifest)
	require.NoError(t, err)

	err = repo.Tag(t.Context(), desc, ref.Reference)
	require.NoError(t, err)
}

func newTestRepo(ref registry.Reference, opts ...RegistryClientOption) *orasremote.Repository {
	repo := &orasremote.Repository{
		Client: &auth.Client{
			Client: &http.Client{
				Transport: http.DefaultTransport.(*http.Transport).Clone(),
			},
		},
		Reference: ref,
	}
	for _, opt := range opts {
		opt(repo)
	}
	return repo
}

func setupRegistry(newServerFn func(http.Handler) *httptest.Server) (*TestRegistry, error) {
	reg := &TestRegistry{}
	reg.server = newServerFn(reg)

	serverURL, err := url.Parse(reg.server.URL)
	if err != nil {
		return nil, err
	}
	reg.url = *serverURL
	return reg, nil
}

func NewRegistryServer() *olareg.Server {
	deleteEnabled := true
	conf := config.Config{
		Storage: config.ConfigStorage{
			StoreType: config.StoreMem,
		},
		API: config.ConfigAPI{
			DeleteEnabled: &deleteEnabled,
		},
		Auth: config.ConfigAuth{
			Handler: func(repo string, access config.AuthAccess, next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if repo == "test/restricted" && access == config.AuthRead {
						user, pass, ok := r.BasicAuth()
						if !ok || user != "user" || pass != "pass" {
							w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
					}
					next.ServeHTTP(w, r)
				})
			},
		},
	}
	conf.SetDefaults()
	return olareg.New(conf)
}
