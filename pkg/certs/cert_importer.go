package certs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/aws/services"
	"sigs.k8s.io/aws-load-balancer-controller/pkg/k8s"
	lbcmetrics "sigs.k8s.io/aws-load-balancer-controller/pkg/metrics/lbc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Tag keys applied to ACM certificates we import on behalf of Kubernetes secrets.
// These let us re-discover (and refuse to clobber) certs we previously imported
// for the same secret across reconciles, restarts, and controller upgrades.
const (
	TagKubernetesSecretName      = "kubernetes.io/secret-name"
	TagKubernetesSecretNamespace = "kubernetes.io/secret-namespace"
	// TagKubernetesSecretHash is a sha256 fingerprint of the imported material
	// (leaf + key + chain). It lets us tell "the secret rotated" apart from
	// "someone else already uploaded a cert for this secret".
	TagKubernetesSecretHash = "kubernetes.io/secret-content-hash"
	// TagManagedBy marks certificates uploaded by this controller, so we can
	// distinguish them from out-of-band imports tagged with the secret name.
	TagManagedBy      = "elbv2.k8s.aws/managed-by"
	TagManagedByValue = "aws-load-balancer-controller"
)

// CertImporter resolves a Kubernetes TLS secret reference to an ACM certificate
// ARN, importing it into ACM the first time and reusing the existing import on
// subsequent reconciles. Implementations must be safe for concurrent use.
type CertImporter interface {
	// ImportSecretAsCertificate returns the ARN of the ACM certificate that
	// holds the contents of the given TLS secret. The secret must already have
	// been fetched by the caller (the model builder owns the SecretsManager).
	ImportSecretAsCertificate(ctx context.Context, secret *corev1.Secret) (string, error)
}

// NewACMCertImporter builds the default importer.
func NewACMCertImporter(acmClient services.ACM, metricsCollector lbcmetrics.MetricCollector, logger logr.Logger) *acmCertImporter {
	return &acmCertImporter{
		acmClient:        acmClient,
		metricsCollector: metricsCollector,
		logger:           logger,
	}
}

var _ CertImporter = &acmCertImporter{}

type acmCertImporter struct {
	acmClient        services.ACM
	metricsCollector lbcmetrics.MetricCollector
	logger           logr.Logger
}

// parsedSecret holds the certificate material extracted from a Kubernetes
// TLS secret, in the shape ACM expects (leaf separated from chain).
type parsedSecret struct {
	// Certificate is the single PEM-encoded leaf certificate.
	Certificate []byte
	// PrivateKey is the PEM-encoded private key.
	PrivateKey []byte
	// CertificateChain is the PEM-encoded chain (zero or more intermediates
	// and an optional root), or nil if the secret had no chain material.
	CertificateChain []byte
	// ContentHash is a stable fingerprint of the material above. Used as a
	// tag on ACM to recognise our own previous imports across reconciles.
	ContentHash string
}

func (i *acmCertImporter) ImportSecretAsCertificate(ctx context.Context, secret *corev1.Secret) (string, error) {
	start := time.Now()
	secretKey := types.NamespacedName{Namespace: secret.Namespace, Name: secret.Name}

	parsed, err := parseTLSSecret(secret)
	if err != nil {
		i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, lbcmetrics.ACMImportResultError, time.Since(start))
		return "", errors.Wrapf(err, "invalid TLS secret %s", secretKey)
	}

	existing, err := i.findExistingForSecret(ctx, secretKey)
	if err != nil {
		i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, lbcmetrics.ACMImportResultError, time.Since(start))
		return "", errors.Wrapf(err, "failed to look up existing ACM certificate for secret %s", secretKey)
	}

	if existing != nil && existing.contentHash == parsed.ContentHash {
		// Steady-state path: ACM already holds exactly this material, tagged
		// for exactly this secret. Reuse the ARN without an API call.
		i.logger.V(1).Info("reusing existing ACM certificate for secret",
			"secret", secretKey, "certificateARN", existing.arn)
		i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, lbcmetrics.ACMImportResultReused, time.Since(start))
		return existing.arn, nil
	}

	// Either no existing cert (fresh import) or the secret rotated since the
	// last import (re-import in place so dependent listeners keep working
	// across cert-manager-style rotations). The ACM ImportCertificate API
	// handles both cases: omit CertificateArn for a brand-new cert, pass it
	// to update the material on an existing one. Note that ACM does NOT
	// accept the Tags field on an update; we have to call AddTagsToCertificate
	// separately to refresh the content-hash tag.
	input := &acm.ImportCertificateInput{
		Certificate: parsed.Certificate,
		PrivateKey:  parsed.PrivateKey,
	}
	if len(parsed.CertificateChain) > 0 {
		input.CertificateChain = parsed.CertificateChain
	}

	resultLabel := lbcmetrics.ACMImportResultImported
	if existing != nil {
		input.CertificateArn = awssdk.String(existing.arn)
		resultLabel = lbcmetrics.ACMImportResultRotated
		i.logger.Info("Kubernetes TLS secret content changed; re-importing into ACM",
			"secret", secretKey, "certificateARN", existing.arn,
			"oldContentHash", existing.contentHash, "newContentHash", parsed.ContentHash)
	} else {
		// First-time import: ACM lets us attach tags atomically with the
		// initial request.
		input.Tags = managedTagsFor(secret, parsed.ContentHash)
		i.logger.Info("importing Kubernetes TLS secret into ACM", "secret", secretKey)
	}

	out, err := i.acmClient.ImportCertificateWithContext(ctx, input)
	if err != nil {
		i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, lbcmetrics.ACMImportResultError, time.Since(start))
		return "", errors.Wrapf(err, "failed to import certificate from secret %s into ACM", secretKey)
	}
	arn := awssdk.ToString(out.CertificateArn)

	if existing != nil {
		// Re-imports don't accept Tags on the request, so push the new hash
		// (and refresh the identity tags so a manual rename can't desync).
		if _, err := i.acmClient.AddTagsToCertificateWithContext(ctx, &acm.AddTagsToCertificateInput{
			CertificateArn: awssdk.String(arn),
			Tags:           managedTagsFor(secret, parsed.ContentHash),
		}); err != nil {
			// We already rotated the material; failing to update the hash tag
			// would just cause the next reconcile to think the cert is stale
			// and rotate again. Surface it but include the ARN so the operator
			// can fix tags out-of-band if needed.
			i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, lbcmetrics.ACMImportResultError, time.Since(start))
			return "", errors.Wrapf(err, "imported new material into ACM certificate %s but failed to update content-hash tag", arn)
		}
	}

	i.logger.Info("ACM certificate ready for secret", "secret", secretKey, "certificateARN", arn, "result", resultLabel)
	i.metricsCollector.ObserveACMCertificateImport(secret.Namespace, secret.Name, resultLabel, time.Since(start))
	return arn, nil
}

// managedTagsFor returns the full set of tags this controller stamps on every
// ACM certificate it manages on behalf of a Kubernetes secret. Re-emitting all
// four tags on rotation is intentional: it lets us correct identity drift
// (e.g. an operator manually edited a tag) at the same time we refresh the
// content hash.
func managedTagsFor(secret *corev1.Secret, contentHash string) []acmtypes.Tag {
	return []acmtypes.Tag{
		{Key: awssdk.String(TagManagedBy), Value: awssdk.String(TagManagedByValue)},
		{Key: awssdk.String(TagKubernetesSecretNamespace), Value: awssdk.String(secret.Namespace)},
		{Key: awssdk.String(TagKubernetesSecretName), Value: awssdk.String(secret.Name)},
		{Key: awssdk.String(TagKubernetesSecretHash), Value: awssdk.String(contentHash)},
	}
}

type existingImport struct {
	arn         string
	contentHash string
}

// findExistingForSecret returns the ACM certificate (if any) that this
// controller previously imported on behalf of the given secret. It matches on
// the secret-name + secret-namespace tags plus our managed-by marker; the
// content-hash tag is returned separately so the caller can decide between
// reuse and conflict.
func (i *acmCertImporter) findExistingForSecret(ctx context.Context, secretKey types.NamespacedName) (*existingImport, error) {
	summaries, err := i.acmClient.ListCertificatesAsList(ctx, &acm.ListCertificatesInput{})
	if err != nil {
		return nil, err
	}
	var match *existingImport
	for _, summary := range summaries {
		arn := awssdk.ToString(summary.CertificateArn)
		resp, err := i.acmClient.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
			CertificateArn: summary.CertificateArn,
		})
		if err != nil {
			return nil, err
		}
		tags := tagSliceToMap(resp.Tags)
		if tags[TagManagedBy] != TagManagedByValue {
			continue
		}
		if tags[TagKubernetesSecretNamespace] != secretKey.Namespace || tags[TagKubernetesSecretName] != secretKey.Name {
			continue
		}
		if match != nil {
			// Two of our own imports for the same secret should never happen,
			// but report it explicitly rather than silently picking one.
			return nil, errors.Errorf("multiple ACM certificates tagged for secret %s (%s and %s); resolve manually", secretKey, match.arn, arn)
		}
		match = &existingImport{arn: arn, contentHash: tags[TagKubernetesSecretHash]}
	}
	return match, nil
}

func tagSliceToMap(tags []acmtypes.Tag) map[string]string {
	out := make(map[string]string, len(tags))
	for _, t := range tags {
		out[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return out
}

// parseTLSSecret pulls the certificate material out of a Kubernetes TLS secret
// and reshapes it for ACM. It accepts either a kubernetes.io/tls secret
// (tls.crt + tls.key, optional ca.crt) or an Opaque secret with the same keys.
//
// ACM's ImportCertificate wants the leaf certificate by itself in Certificate
// and the rest of the chain in CertificateChain. Kubernetes secrets routinely
// concatenate all of those into tls.crt, or stuff a leaf+chain bundle into
// ca.crt. parseTLSSecret normalises both cases.
func parseTLSSecret(secret *corev1.Secret) (*parsedSecret, error) {
	if secret == nil {
		return nil, errors.New("secret is nil")
	}
	tlsCrt, ok := secret.Data[corev1.TLSCertKey]
	if !ok || len(tlsCrt) == 0 {
		return nil, errors.Errorf("secret %s/%s is missing %q", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}
	tlsKey, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok || len(tlsKey) == 0 {
		return nil, errors.Errorf("secret %s/%s is missing %q", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}

	leaf, chainFromTLS, err := splitLeafAndChain(tlsCrt)
	if err != nil {
		return nil, errors.Wrapf(err, "parsing %q", corev1.TLSCertKey)
	}

	// ca.crt is optional and, unlike tls.crt, is expected to hold pure chain
	// material with no leaf of its own (that's the normal cert-manager
	// shape) -- so, unlike tls.crt, we must NOT treat its first block as a
	// disposable "leaf": doing so silently drops the first real intermediate
	// from the chain. Some issuers do populate ca.crt as a convenience
	// leaf+chain copy of tls.crt though, so strip any block that matches the
	// leaf we already extracted before merging, then de-dup at the PEM-block
	// level so a customer who put "leaf + intermediates" in tls.crt AND
	// "intermediates + root" in ca.crt doesn't get duplicate blocks.
	var chainFromCA []byte
	if caCrt, ok := secret.Data[corev1.ServiceAccountRootCAKey]; ok && len(caCrt) > 0 {
		caBlocks, caErr := allCertificateBlocks(caCrt)
		if caErr != nil {
			return nil, errors.Wrapf(caErr, "parsing %q", corev1.ServiceAccountRootCAKey)
		}
		chainFromCA = removeMatchingBlock(caBlocks, leaf)
	}

	combinedChain := mergeChains(chainFromTLS, chainFromCA)

	hash := sha256.New()
	hash.Write(leaf)
	hash.Write([]byte{0})
	hash.Write(tlsKey)
	hash.Write([]byte{0})
	hash.Write(combinedChain)

	return &parsedSecret{
		Certificate:      leaf,
		PrivateKey:       tlsKey,
		CertificateChain: combinedChain,
		ContentHash:      hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

// splitLeafAndChain walks PEM blocks in input and returns the first
// CERTIFICATE block as the leaf and the remainder (re-encoded) as the chain.
// Non-certificate blocks are skipped. Returns an error if no certificate
// block is present.
func splitLeafAndChain(input []byte) (leaf []byte, chain []byte, err error) {
	rest := input
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if !isCertificateBlock(block) {
			continue
		}
		if leaf == nil {
			leaf = pem.EncodeToMemory(block)
			continue
		}
		chain = append(chain, pem.EncodeToMemory(block)...)
	}
	if leaf == nil {
		return nil, nil, errors.New("no PEM CERTIFICATE block found")
	}
	return leaf, chain, nil
}

func isCertificateBlock(block *pem.Block) bool {
	// PEM type "CERTIFICATE" is the standard; some tooling emits "X509
	// CERTIFICATE" or "TRUSTED CERTIFICATE", which ACM also accepts.
	t := strings.ToUpper(block.Type)
	return strings.HasSuffix(t, "CERTIFICATE")
}

// allCertificateBlocks returns every CERTIFICATE-type PEM block in input,
// re-encoded and concatenated in order. Unlike splitLeafAndChain, it makes no
// assumption that the first block is a leaf to be split off -- callers use
// this for inputs (like ca.crt) that are expected to hold pure chain
// material, where treating the first block as a disposable leaf would
// silently drop a real intermediate.
func allCertificateBlocks(input []byte) ([]byte, error) {
	var out []byte
	rest := input
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if !isCertificateBlock(block) {
			continue
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out, nil
}

// removeMatchingBlock returns chain with any PEM block matching target's
// fingerprint removed. Used to strip a leaf that an issuer duplicated into
// ca.crt before that chain material gets merged with the rest of the chain.
func removeMatchingBlock(chain []byte, target []byte) []byte {
	if len(chain) == 0 || len(target) == 0 {
		return chain
	}
	targetKey := blockFingerprint(target)

	var out []byte
	rest := chain
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		encoded := pem.EncodeToMemory(block)
		if blockFingerprint(encoded) == targetKey {
			continue
		}
		out = append(out, encoded...)
	}
	return out
}

// mergeChains concatenates two PEM chains and removes duplicate blocks while
// preserving order (first occurrence wins).
func mergeChains(a, b []byte) []byte {
	combined := append([]byte{}, a...)
	combined = append(combined, b...)
	if len(combined) == 0 {
		return nil
	}

	var out []byte
	seen := make(map[string]struct{})
	rest := combined
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		encoded := pem.EncodeToMemory(block)
		key := blockFingerprint(encoded)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, encoded...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func blockFingerprint(encodedBlock []byte) string {
	// Strip trailing whitespace differences before hashing so semantically
	// identical blocks compare equal.
	trimmed := bytes.TrimSpace(encodedBlock)
	sum := sha256.Sum256(trimmed)
	return hex.EncodeToString(sum[:])
}

// GatewaySecretFetcher is a small adapter that turns a Kubernetes secret
// reference into a *corev1.Secret using the controller's shared SecretsManager.
// It exists so callers can defer the GET until they know they actually need it
// (e.g., only for HTTPS/TLS listeners that have certificateRefs).
type GatewaySecretFetcher struct {
	K8sClient      client.Client
	SecretsManager k8s.SecretsManager
}

// Fetch returns the secret at key and includes its namespaced name in error
// messages so the caller doesn't have to wrap.
func (f *GatewaySecretFetcher) Fetch(ctx context.Context, key types.NamespacedName) (*corev1.Secret, error) {
	if f.SecretsManager == nil || f.K8sClient == nil {
		return nil, fmt.Errorf("GatewaySecretFetcher not initialised")
	}
	secret, err := f.SecretsManager.GetSecret(ctx, f.K8sClient, key)
	if err != nil {
		return nil, errors.Wrapf(err, "fetching TLS secret %s", key)
	}
	return secret, nil
}
