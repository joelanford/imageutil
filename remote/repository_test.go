package remote_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/pkg/sysregistriesv2"
	"github.com/containers/image/v5/types"
	"github.com/joelanford/imageutil/internal/testutil"
	"github.com/joelanford/imageutil/remote"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
)

func TestNewRepository(t *testing.T) {
	secureReg := testutil.SetupHTTPSRegistry(t)
	skipVerifyReg := testutil.SetupHTTPSRegistry(t)
	httpReg := testutil.SetupHTTPRegistry(t)

	defer func() {
		secureReg.Close()
		skipVerifyReg.Close()
		httpReg.Close()
	}()

	secureRef := registry.Reference{Registry: secureReg.Host(), Repository: "test/image", Reference: "v1"}
	skipVerifyRef := registry.Reference{Registry: skipVerifyReg.Host(), Repository: "test/image", Reference: "v1"}
	httpRef := registry.Reference{Registry: httpReg.Host(), Repository: "test/image", Reference: "v1"}

	dockerPerHostCertPath := t.TempDir()
	testutil.CreatePerHostCertDir(t, dockerPerHostCertPath, secureReg.Host(), secureReg.Certificate())
	secureCertPool := x509.NewCertPool()
	secureCertPool.AddCert(secureReg.Certificate())

	type testCase struct {
		name string
		ref  registry.Reference

		setup func(t *testing.T)

		conf *sysregistriesv2.V2RegistriesConf
		auth *testutil.AuthFile

		requireError func(t require.TestingT, err error, msgAndArgs ...interface{})
	}
	testCases := []testCase{
		{
			name: "invalid reference",
			ref:  registry.Reference{Repository: "invalid-reference"},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, errdef.ErrInvalidReference)
			},
		},
		{
			name: "invalid mirror reference",
			ref:  secureRef,
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{
				{
					Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host()},
					Mirrors: []sysregistriesv2.Endpoint{
						{Location: "file://invalid-mirror"},
					},
				},
			}},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, reference.ErrReferenceInvalidFormat)
			},
		},
		{
			name: "invalid registry configuration",
			ref:  secureRef,
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{
				{Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host(), Insecure: true}},
				{Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host(), Insecure: false}},
			}},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "defined multiple times")
			},
		},
		{
			name: "invalid auth configuration",
			ref:  secureRef,
			auth: &testutil.AuthFile{
				AuthConfigs: map[string]testutil.AuthConfig{secureReg.Host(): {
					Auth: "invalid",
				}},
			},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "failed to load credential")
			},
		},
		{
			name: "registry blocked",
			ref:  secureRef,
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{
				{Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host()}, Blocked: true},
			}},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorContains(t, err, "blocked")
			},
		},
		{
			name: "repository not found, no registry config",
			ref:  secureRef,
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, errdef.ErrNotFound)
				require.NotContains(t, err.Error(), "mirrors failed")
				require.ErrorContains(t, err, secureReg.Host())
			},
		},
		{
			name: "repository not found, no mirrors defined",
			ref:  secureRef,
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{
				{Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host()}},
			}},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, errdef.ErrNotFound)
				require.NotContains(t, err.Error(), "mirrors failed")
				require.ErrorContains(t, err, secureReg.Host())
			},
		},
		{
			name: "repository not found, multiple mirrors defined",
			ref:  secureRef,
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{
				{
					Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host()},
					Mirrors: []sysregistriesv2.Endpoint{
						{Location: skipVerifyReg.Host()},
						{Location: httpReg.Host()},
					},
				},
			}},
			requireError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, errdef.ErrNotFound)
				require.ErrorContains(t, err, "mirrors failed")
				require.ErrorContains(t, err, secureReg.Host())
				require.ErrorContains(t, err, skipVerifyReg.Host())
				require.ErrorContains(t, err, httpReg.Host())
			},
		},
		{
			name: "registry is HTTP, config requires secure connection",
			ref:  httpRef,
			requireError: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "server gave HTTP response to HTTPS client")
			},
		},
		{
			name: "registry cert not trusted, config requires secure connection",
			ref:  skipVerifyRef,
			requireError: func(t require.TestingT, err error, i ...interface{}) {
				require.ErrorContains(t, err, "x509: certificate signed by unknown authority")
			},
		},
		{
			name: "registry is HTTP, config allows insecure connection",
			ref:  httpRef,
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, httpRef, testutil.WithHTTPClient(true))
			},
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{{
				Endpoint: sysregistriesv2.Endpoint{Location: httpReg.Host(), Insecure: true},
			}}},
			requireError: require.NoError,
		},
		{
			name: "registry uses self-signed certs, config allows insecure connection",
			ref:  skipVerifyRef,
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, skipVerifyRef, testutil.WithInsecureSkipVerify(true))
			},
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{{
				Endpoint: sysregistriesv2.Endpoint{Location: skipVerifyReg.Host(), Insecure: true},
			}}},
			requireError: require.NoError,
		},
		{
			name: "repository requires authorization",
			ref:  registry.Reference{Registry: secureReg.Host(), Repository: "test/restricted", Reference: "v1"},
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, registry.Reference{Registry: secureReg.Host(), Repository: "test/restricted", Reference: "v1"},
					testutil.WithCredential(auth.Credential{Username: "user", Password: "pass"}),
					testutil.WithRootCAs(secureCertPool),
				)
			},
			auth: &testutil.AuthFile{
				AuthConfigs: map[string]testutil.AuthConfig{secureReg.Host(): {
					Auth: base64.StdEncoding.EncodeToString([]byte("user:pass")),
				}},
			},
			requireError: require.NoError,
		},
		{
			name: "repository found, no registry config",
			ref:  secureRef,
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, secureRef, testutil.WithRootCAs(secureCertPool))
			},
			requireError: require.NoError,
		},
		{
			name: "repository found, from primary",
			ref:  secureRef,
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, secureRef, testutil.WithRootCAs(secureCertPool))
			},
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{{
				Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host(), Insecure: true},
				Mirrors: []sysregistriesv2.Endpoint{
					{Location: httpReg.Host(), Insecure: true},
				},
			}}},
			requireError: require.NoError,
		},
		{
			name: "repository found, from mirror",
			ref:  secureRef,
			setup: func(t *testing.T) {
				testutil.PushAndTagManifest(t, httpRef, testutil.WithHTTPClient(true))
			},
			conf: &sysregistriesv2.V2RegistriesConf{Registries: []sysregistriesv2.Registry{{
				Endpoint: sysregistriesv2.Endpoint{Location: secureReg.Host(), Insecure: true},
				Mirrors: []sysregistriesv2.Endpoint{
					{Location: httpReg.Host(), Insecure: true},
				},
			}}},

			requireError: require.NoError,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r1, r2, r3 := testutil.NewRegistryServer(), testutil.NewRegistryServer(), testutil.NewRegistryServer()
			defer func() {
				require.NoError(t, r1.Close())
				require.NoError(t, r2.Close())
				require.NoError(t, r3.Close())
			}()
			secureReg.SetRegistry(r1)
			skipVerifyReg.SetRegistry(r2)
			httpReg.SetRegistry(r3)

			sys := &types.SystemContext{
				DockerPerHostCertDirPath: dockerPerHostCertPath,
			}
			if tc.conf != nil {
				sys.SystemRegistriesConfPath = testutil.CreateRegistriesConf(t, *tc.conf)
			}
			if tc.auth != nil {
				sys.AuthFilePath = testutil.CreateAuthFile(t, *tc.auth)
			}
			if tc.setup != nil {
				tc.setup(t)
			}
			_, err := remote.NewRepository(t.Context(), sys, tc.ref.String())
			tc.requireError(t, err)
		})
	}
}

// func TestRepository_AuthenticationWithMirrors(t *testing.T) {
// 	primaryTestServer, primaryAddr := setupTestRegistry(t)
// 	defer primaryTestServer.Close()

// 	mirrorTestServer, mirrorAddr := setupTestRegistry(t)
// 	defer mirrorTestServer.Close()

// 	// Create auth.json with credentials for both registries
// 	auths := map[string]map[string]interface{}{
// 		primaryAddr: {
// 			"username": "user1",
// 			"password": "pass1",
// 		},
// 		mirrorAddr: {
// 			"username": "user2",
// 			"password": "pass2",
// 		},
// 	}

// 	authPath := createTempAuthFile(t, auths)

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "%s"
// location = "%s"

//   [[registry.mirror]]
//   location = "%s"
// `, primaryAddr, primaryAddr, mirrorAddr)

// 	confPath := createTempRegistriesConf(t, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 		AuthFilePath:             authPath,
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	// Should use mirror registry with its credentials
// 	repo, err := NewRepository(ctx, sys, primaryAddr+"/test/image:latest")
// 	if err != nil {
// 		t.Fatalf("failed to create repository: %v", err)
// 	}

// 	desc, err := repo.Resolve(ctx, "latest")
// 	if err != nil {
// 		t.Fatalf("failed to resolve reference: %v", err)
// 	}

// 	if desc.MediaType != "application/vnd.oci.image.manifest.v1+json" {
// 		t.Errorf("unexpected media type: %s", desc.MediaType)
// 	}
// }

// func TestRepository_CredentialIsolation(t *testing.T) {
// 	primaryTestServer, primaryAddr := setupTestRegistry(t)
// 	defer primaryTestServer.Close()

// 	mirrorTestServer, mirrorAddr := setupTestRegistry(t)
// 	defer mirrorTestServer.Close()

// 	// Create auth.json with credentials only for primary registry
// 	auths := map[string]map[string]interface{}{
// 		primaryAddr: {
// 			"username": "user1",
// 			"password": "pass1",
// 		},
// 	}

// 	authPath := createTempAuthFile(t, auths)

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "%s"
// location = "%s"

//   [[registry.mirror]]
//   location = "%s"
// `, primaryAddr, primaryAddr, mirrorAddr)

// 	confPath := createTempRegistriesConf(t, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 		AuthFilePath:             authPath,
// 		DockerAuthConfig: &types.DockerAuthConfig{
// 			Username: "user1",
// 			Password: "pass1",
// 		},
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	// Should work - credentials should not be sent to mirror
// 	repo, err := NewRepository(ctx, sys, primaryAddr+"/test/image:latest")
// 	if err != nil {
// 		t.Fatalf("failed to create repository: %v", err)
// 	}

// 	desc, err := repo.Resolve(ctx, "latest")
// 	if err != nil {
// 		t.Fatalf("failed to resolve reference: %v", err)
// 	}

// 	if desc.MediaType != "application/vnd.oci.image.manifest.v1+json" {
// 		t.Errorf("unexpected media type: %s", desc.MediaType)
// 	}
// }

// func TestRepository_ReferenceTranslation(t *testing.T) {
// 	testServer, addr := setupTestRegistry(t)
// 	defer testServer.Close()

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "%s"
// location = "%s"
// `, addr, addr)

// 	confPath := createTempRegistriesConf(t, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	repo, err := NewRepository(ctx, sys, addr+"/test/image")
// 	if err != nil {
// 		t.Fatalf("failed to create repository: %v", err)
// 	}

// 	// Test resolving by tag
// 	desc, err := repo.Resolve(ctx, "latest")
// 	if err != nil {
// 		t.Fatalf("failed to resolve tag: %v", err)
// 	}

// 	if desc.MediaType != "application/vnd.oci.image.manifest.v1+json" {
// 		t.Errorf("unexpected media type: %s", desc.MediaType)
// 	}

// 	// Test resolving by digest (get the digest from the previous resolve)
// 	desc2, err := repo.Resolve(ctx, desc.Digest.String())
// 	if err != nil {
// 		t.Fatalf("failed to resolve digest: %v", err)
// 	}

// 	if desc2.MediaType != desc.MediaType {
// 		t.Errorf("digest and tag resolution should return same manifest")
// 	}
// }

// func TestRepository_RepositoryOptions(t *testing.T) {
// 	testServer, addr := setupTestRegistry(t)
// 	defer testServer.Close()

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "%s"
// location = "%s"
// `, addr, addr)

// 	confPath := createTempRegistriesConf(t, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	// Test with various options
// 	repo, err := NewRepository(ctx, sys, addr+"/test/image",
// 		WithManifestMediaTypes([]string{"application/vnd.oci.image.manifest.v1+json"}),
// 		WithTagListPageSize(50),
// 		WithReferrerListPageSize(100),
// 		WithMaxMetadataBytes(1024*1024),
// 		WithSkipReferrersGC(true),
// 		WithHandleWarning(func(warning remote.Warning) {
// 			// Test warning handler
// 		}),
// 	)
// 	if err != nil {
// 		t.Fatalf("failed to create repository with options: %v", err)
// 	}

// 	if repo.physicalRepo.TagListPageSize != 50 {
// 		t.Errorf("expected TagListPageSize 50, got %d", repo.physicalRepo.TagListPageSize)
// 	}

// 	if repo.physicalRepo.ReferrerListPageSize != 100 {
// 		t.Errorf("expected ReferrerListPageSize 100, got %d", repo.physicalRepo.ReferrerListPageSize)
// 	}

// 	if repo.physicalRepo.MaxMetadataBytes != 1024*1024 {
// 		t.Errorf("expected MaxMetadataBytes 1048576, got %d", repo.physicalRepo.MaxMetadataBytes)
// 	}

// 	if !repo.physicalRepo.SkipReferrersGC {
// 		t.Error("expected SkipReferrersGC to be true")
// 	}
// }

// func TestRepository_MultipleFailuresWithDetails(t *testing.T) {
// 	// Create one working registry
// 	workingTestServer, workingAddr := setupTestRegistry(t)
// 	defer workingTestServer.Close()

// 	// Use non-existent addresses for failing registries
// 	failing1 := "127.0.0.1:1"
// 	failing2 := "127.0.0.1:2"

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "example.com"
// location = "example.com"

//   [[registry.mirror]]
//   location = "%s"

//   [[registry.mirror]]
//   location = "%s"

//   [[registry.mirror]]
//   location = "%s"
// `, failing1, failing2, workingAddr)

// 	confPath := createTempRegistriesConf(t, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	// Should succeed with the working mirror
// 	repo, err := NewRepository(ctx, sys, "example.com/test/image:latest")
// 	if err != nil {
// 		t.Fatalf("failed to create repository: %v", err)
// 	}

// 	desc, err := repo.Resolve(ctx, "latest")
// 	if err != nil {
// 		t.Fatalf("failed to resolve reference: %v", err)
// 	}

// 	if desc.MediaType != "application/vnd.oci.image.manifest.v1+json" {
// 		t.Errorf("unexpected media type: %s", desc.MediaType)
// 	}
// }

// // Benchmark tests
// func BenchmarkRepository_Resolve(b *testing.B) {
// 	testServer, addr := setupTestRegistry(b)
// 	defer testServer.Close()

// 	confContent := fmt.Sprintf(`
// [[registry]]
// prefix = "%s"
// location = "%s"
// `, addr, addr)

// 	confPath := createTempRegistriesConf(b, confContent)

// 	sys := &types.SystemContext{
// 		SystemRegistriesConfPath: confPath,
// 	}

// 	ctx := logr.NewContext(context.Background(), logr.Discard())

// 	repo, err := NewRepository(ctx, sys, addr+"/test/image:latest")
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_, err := repo.Resolve(ctx, "latest")
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }
