package certs

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/aws/services"
	lbcmetrics "sigs.k8s.io/aws-load-balancer-controller/v3/pkg/metrics/lbc"
	logr "sigs.k8s.io/controller-runtime/pkg/log"
)

// PEM helpers --------------------------------------------------------------

// pemBlock builds a minimal valid-looking PEM block with type t and arbitrary
// bytes so we can construct deterministic test fixtures without needing real
// X.509 material. parseTLSSecret only inspects block boundaries and types, so
// the body content can be opaque.
func pemBlock(t, body string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: t, Bytes: []byte(body)})
}

func leafPEM(body string) []byte  { return pemBlock("CERTIFICATE", body) }
func chainPEM(body string) []byte { return pemBlock("CERTIFICATE", body) }

func tlsSecret(ns, name string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Type:       corev1.SecretTypeTLS,
		Data:       data,
	}
}

// pemBlockCount returns how many CERTIFICATE blocks are encoded in b. Used to
// assert chain composition without depending on byte-exact equality.
func pemBlockCount(b []byte) int {
	rest := b
	n := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if isCertificateBlock(block) {
			n++
		}
		rest = remaining
	}
	return n
}

// parseTLSSecret tests ------------------------------------------------------

func Test_parseTLSSecret(t *testing.T) {
	leaf := leafPEM("leaf")
	int1 := chainPEM("intermediate-1")
	int2 := chainPEM("intermediate-2")
	root := chainPEM("root")
	key := []byte("-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBg...\n-----END PRIVATE KEY-----\n")

	tests := []struct {
		name            string
		data            map[string][]byte
		wantErr         string
		wantChainBlocks int
	}{
		{
			name:    "missing tls.crt",
			data:    map[string][]byte{corev1.TLSPrivateKeyKey: key},
			wantErr: "tls.crt",
		},
		{
			name:    "missing tls.key",
			data:    map[string][]byte{corev1.TLSCertKey: leaf},
			wantErr: "tls.key",
		},
		{
			name:    "tls.crt with no PEM block",
			data:    map[string][]byte{corev1.TLSCertKey: []byte("not pem"), corev1.TLSPrivateKeyKey: key},
			wantErr: "no PEM CERTIFICATE block",
		},
		{
			name: "leaf only",
			data: map[string][]byte{
				corev1.TLSCertKey:       leaf,
				corev1.TLSPrivateKeyKey: key,
			},
			wantChainBlocks: 0,
		},
		{
			name: "tls.crt holds leaf+chain (the cert-manager default)",
			data: map[string][]byte{
				corev1.TLSCertKey:       append(append([]byte{}, leaf...), append(int1, int2...)...),
				corev1.TLSPrivateKeyKey: key,
			},
			wantChainBlocks: 2,
		},
		{
			name: "ca.crt supplies the chain separately",
			data: map[string][]byte{
				corev1.TLSCertKey:                  leaf,
				corev1.TLSPrivateKeyKey:            key,
				corev1.ServiceAccountRootCAKey:     append(append([]byte{}, int1...), root...),
			},
			wantChainBlocks: 2,
		},
		{
			name: "tls.crt and ca.crt both carry intermediates — dedup",
			data: map[string][]byte{
				corev1.TLSCertKey:              append(append([]byte{}, leaf...), int1...),
				corev1.TLSPrivateKeyKey:        key,
				corev1.ServiceAccountRootCAKey: append(append([]byte{}, int1...), root...),
			},
			wantChainBlocks: 2, // int1 dedup'd, plus root
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTLSSecret(tlsSecret("ns", "s", tc.data))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.NotEmpty(t, got.ContentHash, "content hash must be set")
			assert.Equal(t, 1, pemBlockCount(got.Certificate), "leaf must be a single block")
			assert.Equal(t, tc.wantChainBlocks, pemBlockCount(got.CertificateChain))
		})
	}
}

func Test_parseTLSSecret_HashIsStable(t *testing.T) {
	// Same material → same hash, regardless of map iteration order or repeated
	// invocations. This is the invariant that makes idempotent reconciliation
	// safe; if it ever regresses, every reconcile would look like a rotation.
	s := tlsSecret("ns", "s", map[string][]byte{
		corev1.TLSCertKey:       leafPEM("leaf"),
		corev1.TLSPrivateKeyKey: []byte("key"),
	})
	a, err := parseTLSSecret(s)
	require.NoError(t, err)
	b, err := parseTLSSecret(s)
	require.NoError(t, err)
	assert.Equal(t, a.ContentHash, b.ContentHash)
}

func Test_parseTLSSecret_HashChangesOnRotation(t *testing.T) {
	base := tlsSecret("ns", "s", map[string][]byte{
		corev1.TLSCertKey:       leafPEM("leaf-v1"),
		corev1.TLSPrivateKeyKey: []byte("key"),
	})
	rotated := tlsSecret("ns", "s", map[string][]byte{
		corev1.TLSCertKey:       leafPEM("leaf-v2"),
		corev1.TLSPrivateKeyKey: []byte("key"),
	})
	a, err := parseTLSSecret(base)
	require.NoError(t, err)
	b, err := parseTLSSecret(rotated)
	require.NoError(t, err)
	assert.NotEqual(t, a.ContentHash, b.ContentHash)
}

// ImportSecretAsCertificate tests ------------------------------------------

// fakeCollector captures result labels so tests can assert which path was taken
// without coupling to the prometheus internals.
type fakeCollector struct {
	lbcmetrics.MetricCollector
	lastResult   string
	lastDuration time.Duration
}

func (f *fakeCollector) ObserveACMCertificateImport(_ string, _ string, result string, d time.Duration) {
	f.lastResult = result
	f.lastDuration = d
}

func newImporter(t *testing.T) (*acmCertImporter, *services.MockACM, *fakeCollector, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	mockACM := services.NewMockACM(ctrl)
	col := &fakeCollector{MetricCollector: newNoopCollector()}
	i := NewACMCertImporter(mockACM, col, logr.Log)
	return i, mockACM, col, ctrl
}

// newNoopCollector returns an embeddable collector that does nothing for the
// methods we don't override on fakeCollector.
func newNoopCollector() lbcmetrics.MetricCollector { return noopCollector{} }

type noopCollector struct{}

func (noopCollector) ObservePodReadinessGateReady(_ string, _ string, _ time.Duration) {}
func (noopCollector) ObserveQUICTargetMissingServerId(_ string, _ string)               {}
func (noopCollector) ObserveControllerReconcileError(_ string, _ string)                {}
func (noopCollector) ObserveControllerReconcileLatency(_ string, _ string, fn func())   { fn() }
func (noopCollector) ObserveWebhookValidationError(_ string, _ string)                  {}
func (noopCollector) ObserveWebhookMutationError(_ string, _ string)                    {}
func (noopCollector) ObserveACMCertificateImport(_ string, _ string, _ string, _ time.Duration) {
}
func (noopCollector) StartCollectTopTalkers(_ context.Context) {}
func (noopCollector) StartCollectCacheSize(_ context.Context)  {}

func managedSummary(arn string) acmtypes.CertificateSummary {
	return acmtypes.CertificateSummary{CertificateArn: awssdk.String(arn)}
}

func managedTags(ns, name, hash string) *acm.ListTagsForCertificateOutput {
	return &acm.ListTagsForCertificateOutput{Tags: []acmtypes.Tag{
		{Key: awssdk.String(TagManagedBy), Value: awssdk.String(TagManagedByValue)},
		{Key: awssdk.String(TagKubernetesSecretNamespace), Value: awssdk.String(ns)},
		{Key: awssdk.String(TagKubernetesSecretName), Value: awssdk.String(name)},
		{Key: awssdk.String(TagKubernetesSecretHash), Value: awssdk.String(hash)},
	}}
}

func validSecret() *corev1.Secret {
	return tlsSecret("team-a", "my-tls", map[string][]byte{
		corev1.TLSCertKey:       leafPEM("leaf"),
		corev1.TLSPrivateKeyKey: []byte("private-key-bytes"),
	})
}

func Test_ImportSecretAsCertificate_FreshImport(t *testing.T) {
	imp, mockACM, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	secret := validSecret()

	// No managed certificates exist yet.
	mockACM.EXPECT().ListCertificatesAsList(gomock.Any(), gomock.Any()).Return(nil, nil)

	// Expect ImportCertificate with tags attached atomically and no CertificateArn.
	mockACM.EXPECT().
		ImportCertificateWithContext(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, in *acm.ImportCertificateInput) (*acm.ImportCertificateOutput, error) {
			assert.Nil(t, in.CertificateArn, "fresh import must not set CertificateArn")
			assert.NotEmpty(t, in.Certificate)
			assert.NotEmpty(t, in.PrivateKey)
			// Inspect tags
			tagMap := tagSliceToMap(in.Tags)
			assert.Equal(t, TagManagedByValue, tagMap[TagManagedBy])
			assert.Equal(t, "team-a", tagMap[TagKubernetesSecretNamespace])
			assert.Equal(t, "my-tls", tagMap[TagKubernetesSecretName])
			assert.NotEmpty(t, tagMap[TagKubernetesSecretHash])
			return &acm.ImportCertificateOutput{CertificateArn: awssdk.String("arn:aws:acm:us-west-2:1:certificate/new")}, nil
		})

	arn, err := imp.ImportSecretAsCertificate(context.Background(), secret)
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:acm:us-west-2:1:certificate/new", arn)
	assert.Equal(t, lbcmetrics.ACMImportResultImported, col.lastResult)
}

func Test_ImportSecretAsCertificate_ReusesWhenHashMatches(t *testing.T) {
	imp, mockACM, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	secret := validSecret()

	// Pre-compute the hash so we can pretend an earlier import recorded it.
	parsed, err := parseTLSSecret(secret)
	require.NoError(t, err)

	mockACM.EXPECT().ListCertificatesAsList(gomock.Any(), gomock.Any()).
		Return([]acmtypes.CertificateSummary{managedSummary("arn:existing")}, nil)
	mockACM.EXPECT().ListTagsForCertificate(gomock.Any(), gomock.Any()).
		Return(managedTags(secret.Namespace, secret.Name, parsed.ContentHash), nil)

	// Critical: no ImportCertificate / AddTags calls in the reuse path.
	arn, err := imp.ImportSecretAsCertificate(context.Background(), secret)
	require.NoError(t, err)
	assert.Equal(t, "arn:existing", arn)
	assert.Equal(t, lbcmetrics.ACMImportResultReused, col.lastResult)
}

func Test_ImportSecretAsCertificate_RotatesInPlaceWhenHashDiffers(t *testing.T) {
	imp, mockACM, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	secret := validSecret()

	mockACM.EXPECT().ListCertificatesAsList(gomock.Any(), gomock.Any()).
		Return([]acmtypes.CertificateSummary{managedSummary("arn:stale")}, nil)
	mockACM.EXPECT().ListTagsForCertificate(gomock.Any(), gomock.Any()).
		Return(managedTags(secret.Namespace, secret.Name, "stale-hash"), nil)

	// Re-import must target the existing ARN, must NOT include Tags inline,
	// and must be followed by AddTagsToCertificate with the fresh hash.
	mockACM.EXPECT().
		ImportCertificateWithContext(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, in *acm.ImportCertificateInput) (*acm.ImportCertificateOutput, error) {
			require.NotNil(t, in.CertificateArn, "rotation must target an ARN")
			assert.Equal(t, "arn:stale", awssdk.ToString(in.CertificateArn))
			assert.Empty(t, in.Tags, "ACM rejects Tags on re-imports; controller must use AddTagsToCertificate")
			return &acm.ImportCertificateOutput{CertificateArn: awssdk.String("arn:stale")}, nil
		})
	mockACM.EXPECT().
		AddTagsToCertificateWithContext(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, in *acm.AddTagsToCertificateInput) (*acm.AddTagsToCertificateOutput, error) {
			assert.Equal(t, "arn:stale", awssdk.ToString(in.CertificateArn))
			tagMap := tagSliceToMap(in.Tags)
			assert.NotEqual(t, "stale-hash", tagMap[TagKubernetesSecretHash])
			assert.NotEmpty(t, tagMap[TagKubernetesSecretHash])
			return &acm.AddTagsToCertificateOutput{}, nil
		})

	arn, err := imp.ImportSecretAsCertificate(context.Background(), secret)
	require.NoError(t, err)
	assert.Equal(t, "arn:stale", arn)
	assert.Equal(t, lbcmetrics.ACMImportResultRotated, col.lastResult)
}

func Test_ImportSecretAsCertificate_SkipsForeignTaggedCerts(t *testing.T) {
	// A certificate tagged for our secret name/namespace but without our
	// managed-by marker is treated as a foreign import; we must not touch it.
	imp, mockACM, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	secret := validSecret()

	mockACM.EXPECT().ListCertificatesAsList(gomock.Any(), gomock.Any()).
		Return([]acmtypes.CertificateSummary{managedSummary("arn:foreign")}, nil)
	mockACM.EXPECT().ListTagsForCertificate(gomock.Any(), gomock.Any()).
		Return(&acm.ListTagsForCertificateOutput{Tags: []acmtypes.Tag{
			// Same secret tags, but NO managed-by marker.
			{Key: awssdk.String(TagKubernetesSecretNamespace), Value: awssdk.String(secret.Namespace)},
			{Key: awssdk.String(TagKubernetesSecretName), Value: awssdk.String(secret.Name)},
		}}, nil)

	mockACM.EXPECT().
		ImportCertificateWithContext(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, in *acm.ImportCertificateInput) (*acm.ImportCertificateOutput, error) {
			assert.Nil(t, in.CertificateArn, "foreign cert must be ignored, leading to a fresh import")
			return &acm.ImportCertificateOutput{CertificateArn: awssdk.String("arn:ours")}, nil
		})

	arn, err := imp.ImportSecretAsCertificate(context.Background(), secret)
	require.NoError(t, err)
	assert.Equal(t, "arn:ours", arn)
	assert.Equal(t, lbcmetrics.ACMImportResultImported, col.lastResult)
}

func Test_ImportSecretAsCertificate_ErrorsOnMultipleOwnedMatches(t *testing.T) {
	imp, mockACM, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	secret := validSecret()

	mockACM.EXPECT().ListCertificatesAsList(gomock.Any(), gomock.Any()).
		Return([]acmtypes.CertificateSummary{managedSummary("arn:a"), managedSummary("arn:b")}, nil)
	mockACM.EXPECT().ListTagsForCertificate(gomock.Any(), gomock.Any()).
		Return(managedTags(secret.Namespace, secret.Name, "h1"), nil)
	mockACM.EXPECT().ListTagsForCertificate(gomock.Any(), gomock.Any()).
		Return(managedTags(secret.Namespace, secret.Name, "h2"), nil)

	_, err := imp.ImportSecretAsCertificate(context.Background(), secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple ACM certificates tagged for secret")
	assert.Equal(t, lbcmetrics.ACMImportResultError, col.lastResult)
}

func Test_ImportSecretAsCertificate_ErrorsOnInvalidSecret(t *testing.T) {
	imp, _, col, ctrl := newImporter(t)
	defer ctrl.Finish()
	bad := tlsSecret("ns", "s", map[string][]byte{
		// missing tls.crt entirely
		corev1.TLSPrivateKeyKey: []byte("key"),
	})
	_, err := imp.ImportSecretAsCertificate(context.Background(), bad)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid TLS secret"), err.Error())
	assert.Equal(t, lbcmetrics.ACMImportResultError, col.lastResult)
}
