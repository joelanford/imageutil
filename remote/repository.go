package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/pkg/docker/config"
	"github.com/containers/image/v5/pkg/sysregistriesv2"
	"github.com/containers/image/v5/pkg/tlsclientconfig"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage/pkg/fileutils"
	"github.com/containers/storage/pkg/homedir"
	"github.com/go-logr/logr"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
)

var _ oras.GraphTarget = (*Repository)(nil)

type Repository struct {
	// logicalRepo is the user-facing reference. We don't actually use this
	// to communicate with the remote registry, but it provides useful
	// functionality for presenting the public API around the logical
	// repository, not the underlying physical repository.
	logicalRepo *remote.Repository

	// Repository is the physicalRepo that is configured to use the
	// mirror that was chosen during initialization. We use this to
	// communicate with the underlying repository.
	physicalRepo *remote.Repository
}

type RepositoryOption func(*Repository)

func WithManifestMediaTypes(mediaTypes []string) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.ManifestMediaTypes = mediaTypes
	}
}

func WithTagListPageSize(tagListPageSize int) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.TagListPageSize = tagListPageSize
	}
}
func WithReferrerListPageSize(referrerListPageSize int) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.ReferrerListPageSize = referrerListPageSize
	}
}
func WithMaxMetadataBytes(maxMetadataBytes int64) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.MaxMetadataBytes = maxMetadataBytes
	}
}
func WithSkipReferrersGC(skipReferrersGC bool) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.SkipReferrersGC = skipReferrersGC
	}
}
func WithHandleWarning(handleWarning func(warning remote.Warning)) RepositoryOption {
	return func(r *Repository) {
		r.physicalRepo.HandleWarning = handleWarning
	}
}

func (r *Repository) SetReferrersCapability(capable bool) error {
	return r.SetReferrersCapability(capable)
}

func (r *Repository) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	return r.physicalRepo.Fetch(ctx, desc)
}

func (r *Repository) Push(ctx context.Context, desc ocispec.Descriptor, reader io.Reader) error {
	return r.physicalRepo.Push(ctx, desc, reader)
}

func (r *Repository) Mount(ctx context.Context, desc ocispec.Descriptor, fromRepo string, getContent func() (io.ReadCloser, error)) error {
	return r.physicalRepo.Mount(ctx, desc, fromRepo, getContent)
}

func (r *Repository) Exists(ctx context.Context, desc ocispec.Descriptor) (bool, error) {
	return r.physicalRepo.Exists(ctx, desc)
}

func (r *Repository) Delete(ctx context.Context, desc ocispec.Descriptor) error {
	return r.physicalRepo.Delete(ctx, desc)
}

func (r *Repository) Blobs() registry.BlobStore { return r.physicalRepo.Blobs() }

func (r *Repository) Manifests() registry.ManifestStore { return r.physicalRepo.Manifests() }

func (r *Repository) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	physicalRef, err := r.translateLogicalToPhysicalReference(ref)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return r.physicalRepo.Resolve(ctx, physicalRef.String())
}

func (r *Repository) Tag(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	physicalRef, err := r.translateLogicalToPhysicalReference(ref)
	if err != nil {
		return err
	}
	return r.physicalRepo.Tag(ctx, desc, physicalRef.String())
}

func (r *Repository) PushReference(ctx context.Context, desc ocispec.Descriptor, reader io.Reader, ref string) error {
	physicalRef, err := r.translateLogicalToPhysicalReference(ref)
	if err != nil {
		return err
	}
	return r.physicalRepo.PushReference(ctx, desc, reader, physicalRef.String())
}

func (r *Repository) FetchReference(ctx context.Context, ref string) (ocispec.Descriptor, io.ReadCloser, error) {
	physicalRef, err := r.translateLogicalToPhysicalReference(ref)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	return r.physicalRepo.FetchReference(ctx, physicalRef.String())
}

func (r *Repository) ParseReference(ref string) (registry.Reference, error) {
	return r.logicalRepo.ParseReference(ref)
}

func (r *Repository) Tags(ctx context.Context, last string, fn func([]string) error) error {
	return r.physicalRepo.Tags(ctx, last, fn)
}

func (r *Repository) Predecessors(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	return r.physicalRepo.Predecessors(ctx, desc)
}

func (r *Repository) Referrers(ctx context.Context, desc ocispec.Descriptor, artifactType string, fn func([]ocispec.Descriptor) error) error {
	return r.physicalRepo.Referrers(ctx, desc, artifactType, fn)
}

func (r *Repository) translateLogicalToPhysicalReference(ref string) (*registry.Reference, error) {
	logicalRef, err := r.logicalRepo.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	return &registry.Reference{
		Registry:   r.physicalRepo.Reference.Registry,
		Repository: r.physicalRepo.Reference.Repository,
		Reference:  logicalRef.Reference,
	}, nil
}

func NewRepository(ctx context.Context, sys *types.SystemContext, ref string, opts ...RepositoryOption) (*Repository, error) {
	logicalRef, err := reference.ParseNamed(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errdef.ErrInvalidReference, err)
	}

	reg, err := sysregistriesv2.FindRegistry(sys, ref)
	if err != nil {
		return nil, err
	}
	if reg == nil {
		reg = &sysregistriesv2.Registry{
			Prefix: logicalRef.Name(),
			Endpoint: sysregistriesv2.Endpoint{
				Location: logicalRef.Name(),
			},
		}
	}

	if reg.Blocked {
		return nil, fmt.Errorf("registry %s is blocked in %s", reg.Prefix, sysregistriesv2.ConfigurationSourceDescription(sys))
	}

	pullSources, err := reg.PullSourcesFromReference(logicalRef)
	if err != nil {
		return nil, err
	}

	physicalRepo, err := chooseRepository(ctx, sys, logicalRef, pullSources, opts...)
	if err != nil {
		return nil, err
	}

	repo := &Repository{
		logicalRepo:  &remote.Repository{Reference: namedRefToRegistryReference(logicalRef)},
		physicalRepo: physicalRepo,
	}
	return repo, nil
}

func namedRefToRegistryReference(ref reference.Named) registry.Reference {
	out := registry.Reference{
		Registry:   reference.Domain(ref),
		Repository: reference.Path(ref),
	}
	switch typedRef := ref.(type) {
	case reference.Tagged:
		out.Reference = typedRef.Tag()
	case reference.Digested:
		out.Reference = typedRef.Digest().String()
	}
	return out
}

func chooseRepository(ctx context.Context, sys *types.SystemContext, namedRef reference.Named, pullSources []sysregistriesv2.PullSource, opts ...RepositoryOption) (*remote.Repository, error) {
	var attempts []attempt
	l := logr.FromContextOrDiscard(ctx).V(2)

	for _, pullSource := range pullSources {
		l.Info("trying pull source", "location", pullSource.Reference)
		repo, err := newRepository(sys, namedRef, pullSource, opts...)
		if err != nil {
			attempts = append(attempts, attempt{
				ref: pullSource.Reference.String(),
				err: err,
			})
			continue
		}
		if err := resolveRef(ctx, repo, pullSource.Reference); err != nil {
			attempts = append(attempts, attempt{
				ref: pullSource.Reference.String(),
				err: err,
			})
			continue
		}
		l.Info("choose pull source", "location", pullSource.Reference)
		return repo, nil
	}
	return nil, attemptsError(attempts)
}

type attempt struct {
	ref string
	err error
}

func attemptsError(attempts []attempt) error {
	switch len(attempts) {
	case 0:
		panic("no attempts were made")
	case 1:
		return attempts[0].err
	default:
		primary := &attempts[len(attempts)-1]
		extras := []string{}
		for _, at := range attempts {
			extras = append(extras, fmt.Sprintf("[%s: %v]", at.ref, at.err))
		}
		return fmt.Errorf("%s: %w; (mirrors failed: %s)", primary.ref, primary.err, strings.Join(extras, "\n"))
	}
}

func newRepository(sys *types.SystemContext, logicalRef reference.Named, pullSource sysregistriesv2.PullSource, opts ...RepositoryOption) (*remote.Repository, error) {
	endpointSys := sys
	// sys.DockerAuthConfig does not explicitly specify a registry; we must not blindly send the credentials intended for the primary endpoint to mirrors.
	if endpointSys != nil && endpointSys.DockerAuthConfig != nil && reference.Domain(pullSource.Reference) != reference.Domain(logicalRef) {
		endpointSysCopy := *endpointSys
		endpointSysCopy.DockerAuthConfig = nil
		endpointSysCopy.DockerBearerRegistryToken = ""
		endpointSys = &endpointSysCopy
	}

	cred, err := getCredential(endpointSys, pullSource.Reference)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential for %s: %w", pullSource.Reference, err)
	}

	repo, err := remote.NewRepository(pullSource.Reference.Name())
	if err != nil {
		return nil, err
	}

	optWrapper := &Repository{physicalRepo: repo}
	for _, opt := range opts {
		opt(optWrapper)
	}

	base := tlsclientconfig.NewTransport()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: pullSource.Endpoint.Insecure}
	if sys != nil && sys.DockerInsecureSkipTLSVerify != types.OptionalBoolUndefined {
		base.TLSClientConfig.InsecureSkipVerify = sys.DockerInsecureSkipTLSVerify == types.OptionalBoolTrue
	}

	certDir, err := dockerCertDir(sys, reference.Domain(pullSource.Reference))
	if err != nil {
		return nil, err
	}
	if err := tlsclientconfig.SetupCertificates(certDir, base.TLSClientConfig); err != nil {
		return nil, err
	}

	cl := &auth.Client{
		Client: &http.Client{
			Transport: retry.NewTransport(newFallbackTransport(base, pullSource.Endpoint.Insecure)),
		},
		Cache: auth.DefaultCache,
		Credential: func(_ context.Context, _ string) (auth.Credential, error) {
			return cred, nil
		},
	}
	if sys != nil && sys.DockerRegistryUserAgent != "" {
		cl.SetUserAgent(sys.DockerRegistryUserAgent)
	}
	repo.Client = cl

	return repo, nil
}

func resolveRef(ctx context.Context, r *remote.Repository, ref reference.Named) error {
	switch ref.(type) {
	case reference.Tagged, reference.Digested:
		if _, err := r.Resolve(ctx, ref.String()); err != nil {
			return err
		}
		return nil
	}
	exists, err := repoExists(ctx, r)
	if err != nil {
		return err
	}
	if !exists {
		return errdef.ErrNotFound
	}
	return nil
}

func repoExists(ctx context.Context, r *remote.Repository) (bool, error) {
	ctx = auth.AppendRepositoryScope(ctx, r.Reference, auth.ActionPull)
	url := buildRepositoryTagListURL(r.PlainHTTP, r.Reference)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// buildScheme returns HTTP scheme used to access the remote registry.
func buildScheme(plainHTTP bool) string {
	if plainHTTP {
		return "http"
	}
	return "https"
}

// buildRepositoryBaseURL builds the base endpoint of the remote repository.
// Format: <scheme>://<registry>/v2/<repository>
func buildRepositoryBaseURL(plainHTTP bool, ref registry.Reference) string {
	return fmt.Sprintf("%s://%s/v2/%s", buildScheme(plainHTTP), ref.Host(), ref.Repository)
}

// buildRepositoryTagListURL builds the URL for accessing the tag list API.
// Format: <scheme>://<registry>/v2/<repository>/tags/list
// Reference: https://distribution.github.io/distribution/spec/api/#tags
func buildRepositoryTagListURL(plainHTTP bool, ref registry.Reference) string {
	return buildRepositoryBaseURL(plainHTTP, ref) + "/tags/list"
}

func getCredential(sys *types.SystemContext, ref reference.Named) (auth.Credential, error) {
	cred, err := config.GetCredentialsForRef(sys, ref)
	if err != nil {
		return auth.EmptyCredential, err
	}
	if cred.IdentityToken != "" {
		cred.Password = cred.IdentityToken
	}
	return auth.Credential{Username: cred.Username, Password: cred.Password}, nil
}

type certPath struct {
	path     string
	absolute bool
}

var (
	homeCertDir     = filepath.FromSlash(".config/containers/certs.d")
	perHostCertDirs = []certPath{
		{path: "/etc/containers/certs.d", absolute: true},
		{path: "/etc/docker/certs.d", absolute: true},
	}
)

// dockerCertDir returns a path to a directory to be consumed by tlsclientconfig.SetupCertificates() depending on ctx and hostPort.
func dockerCertDir(sys *types.SystemContext, hostPort string) (string, error) {
	if sys != nil && sys.DockerCertPath != "" {
		return sys.DockerCertPath, nil
	}
	if sys != nil && sys.DockerPerHostCertDirPath != "" {
		return filepath.Join(sys.DockerPerHostCertDirPath, hostPort), nil
	}

	var (
		hostCertDir     string
		fullCertDirPath string
	)

	for _, perHostCertDir := range append([]certPath{{path: filepath.Join(homedir.Get(), homeCertDir), absolute: false}}, perHostCertDirs...) {
		if sys != nil && sys.RootForImplicitAbsolutePaths != "" && perHostCertDir.absolute {
			hostCertDir = filepath.Join(sys.RootForImplicitAbsolutePaths, perHostCertDir.path)
		} else {
			hostCertDir = perHostCertDir.path
		}

		fullCertDirPath = filepath.Join(hostCertDir, hostPort)
		err := fileutils.Exists(fullCertDirPath)
		if err == nil {
			break
		}
		if os.IsNotExist(err) {
			continue
		}
		if os.IsPermission(err) {
			logrus.Debugf("error accessing certs directory due to permissions: %v", err)
			continue
		}
		return "", err
	}
	return fullCertDirPath, nil
}

type fallbackTransport struct {
	rt http.RoundTripper
}

func (t *fallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err == nil || !errors.As(err, &tls.RecordHeaderError{}) {
		return resp, err
	}

	req.URL.Scheme = "http"
	return t.rt.RoundTrip(req)
}

func newFallbackTransport(base http.RoundTripper, insecure bool) http.RoundTripper {
	if !insecure {
		return base
	}
	return &fallbackTransport{rt: base}
}
