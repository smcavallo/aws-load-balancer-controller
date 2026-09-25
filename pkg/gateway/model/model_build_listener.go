package model

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/shared_utils"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	elbv2gw "sigs.k8s.io/aws-load-balancer-controller/v3/apis/gateway/v1"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/aws/services"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/certs"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/gateway/routeutils"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/k8s"
	acmModel "sigs.k8s.io/aws-load-balancer-controller/v3/pkg/model/acm"
	"sigs.k8s.io/aws-load-balancer-controller/v3/pkg/model/core"
	elbv2model "sigs.k8s.io/aws-load-balancer-controller/v3/pkg/model/elbv2"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TODO: Add more relevant info like TLS settings and hostnames later wherever applicable
type gwListenerConfig struct {
	protocol        elbv2model.Protocol
	hostnames       sets.Set[string]
	certificateRefs []gwv1.SecretObjectReference
}

const (
	certRefSecretKind      = "Secret"
	certRefCoreAPIGroup    = ""
	certRefGatewayAPIGroup = "gateway.networking.k8s.io"
	certRefGatewayKind     = "Gateway"
)

type listenerBuilder interface {
	buildListeners(ctx context.Context, stack core.Stack, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, listeners []gwv1.Listener, routes map[int32][]routeutils.RouteDescriptor, lbConf elbv2gw.LoadBalancerConfiguration) ([]types.NamespacedName, error)
}

type listenerBuilderImpl struct {
	elbv2Client                services.ELBV2
	k8sClient                  client.Client
	loadBalancerType           elbv2model.LoadBalancerType
	clusterName                string
	tagHelper                  tagHelper
	tgBuilder                  targetGroupBuilder
	defaultSSLPolicy           string
	secretsManager             k8s.SecretsManager
	certDiscovery              certs.CertDiscovery
	certImporter               certs.CertImporter
	targetGroupNameToArnMapper shared_utils.TargetGroupARNMapper
	logger                     logr.Logger
}

func (l listenerBuilderImpl) buildListeners(ctx context.Context, stack core.Stack, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, listeners []gwv1.Listener, routes map[int32][]routeutils.RouteDescriptor, lbCfg elbv2gw.LoadBalancerConfiguration) ([]types.NamespacedName, error) {
	gwLsCfgs, err := mapGatewayListenerConfigsByPort(listeners, routes)
	if err != nil {
		return nil, err
	}
	secrets := make([]types.NamespacedName, 0)
	gwLsPorts := sets.Int32KeySet(gwLsCfgs)
	portsWithRoutes := sets.Int32KeySet(routes)
	// Materialise the listener only if listener has associated routes
	if len(gwLsPorts.Intersection(portsWithRoutes).List()) != 0 {
		lbLsCfgs := mapLoadBalancerListenerConfigsByPort(lbCfg, gwLsCfgs)
		for _, port := range gwLsPorts.Intersection(portsWithRoutes).List() {
			ls, certSecretKeys, err := l.buildListener(ctx, stack, lb, gw, port, routes[port], lbCfg, gwLsCfgs[port], lbLsCfgs[port])
			if err != nil {
				return nil, err
			}
			secrets = append(secrets, certSecretKeys...)

			if ls == nil {
				continue
			}

			// build rules only for L7 gateways
			if l.loadBalancerType == elbv2model.LoadBalancerTypeApplication {
				secretKeys, err := l.buildListenerRules(ctx, stack, ls, lb.Spec.IPAddressType, gw, port, routes)
				if err != nil {
					return nil, err
				}
				secrets = append(secrets, secretKeys...)
			}
		}
	}

	return secrets, nil
}

func (l listenerBuilderImpl) buildListener(ctx context.Context, stack core.Stack, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, port int32, routes []routeutils.RouteDescriptor, lbCfg elbv2gw.LoadBalancerConfiguration, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*elbv2model.Listener, []types.NamespacedName, error) {
	var listenerSpec *elbv2model.ListenerSpec
	var certSecretKeys []types.NamespacedName

	var err error
	if l.loadBalancerType == elbv2model.LoadBalancerTypeApplication {
		listenerSpec, certSecretKeys, err = l.buildL7ListenerSpec(ctx, lb, gw, lbCfg, port, gwLsCfg, lbLsCfg)
	} else {
		listenerSpec, certSecretKeys, err = l.buildL4ListenerSpec(ctx, stack, lb, gw, lbCfg, port, routes, gwLsCfg, lbLsCfg)
	}
	if err != nil {
		return nil, nil, err
	}

	if listenerSpec == nil {
		return nil, certSecretKeys, nil
	}

	lsResID := fmt.Sprintf("%v", port)
	return elbv2model.NewListener(stack, lsResID, *listenerSpec), certSecretKeys, nil
}

func (l listenerBuilderImpl) buildListenerSpec(ctx context.Context, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, port int32, lbCfg elbv2gw.LoadBalancerConfiguration, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*elbv2model.ListenerSpec, []types.NamespacedName, error) {
	tags, err := l.buildListenerTags(lbCfg)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}
	lsAttributes, attributesErr := buildListenerAttributes(lbLsCfg)
	if attributesErr != nil {
		return &elbv2model.ListenerSpec{}, nil, attributesErr
	}
	sslPolicy, sslPolicyErr := l.buildSSLPolicy(gwLsCfg, lbLsCfg)
	if sslPolicyErr != nil {
		return &elbv2model.ListenerSpec{}, nil, sslPolicyErr
	}
	certificates, certSecretKeys, certsErr := l.buildCertificates(ctx, gw, port, gwLsCfg, lbLsCfg)
	if certsErr != nil {
		return &elbv2model.ListenerSpec{}, nil, certsErr
	}

	// Apply QUIC protocol upgrade if enabled
	protocol := gwLsCfg.protocol
	if lbLsCfg != nil && lbLsCfg.QuicEnabled != nil && *lbLsCfg.QuicEnabled {
		switch protocol {
		case elbv2model.ProtocolUDP:
			protocol = elbv2model.ProtocolQUIC
		case elbv2model.ProtocolTCP_UDP:
			protocol = elbv2model.ProtocolTCP_QUIC
		default:
			return &elbv2model.ListenerSpec{}, nil, fmt.Errorf("QUIC protocol upgrade not supported for protocol %v", protocol)
		}
	}

	listenerSpec := &elbv2model.ListenerSpec{
		LoadBalancerARN:    lb.LoadBalancerARN(),
		Port:               port,
		Protocol:           protocol,
		Certificates:       certificates,
		SSLPolicy:          sslPolicy,
		Tags:               tags,
		ListenerAttributes: lsAttributes,
	}
	return listenerSpec, certSecretKeys, nil
}

func (l listenerBuilderImpl) buildL7ListenerSpec(ctx context.Context, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, lbCfg elbv2gw.LoadBalancerConfiguration, port int32, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*elbv2model.ListenerSpec, []types.NamespacedName, error) {
	listenerSpec, certSecretKeys, err := l.buildListenerSpec(ctx, lb, gw, port, lbCfg, gwLsCfg, lbLsCfg)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}
	listenerSpec.DefaultActions = buildL7ListenerDefaultActions()
	mutualAuth, err := l.buildMutualAuthenticationAttributes(ctx, gwLsCfg, lbLsCfg)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}
	listenerSpec.MutualAuthentication = mutualAuth
	return listenerSpec, certSecretKeys, nil
}

func (l listenerBuilderImpl) buildL4ListenerSpec(ctx context.Context, stack core.Stack, lb *elbv2model.LoadBalancer, gw *gwv1.Gateway, lbCfg elbv2gw.LoadBalancerConfiguration, port int32, routes []routeutils.RouteDescriptor, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*elbv2model.ListenerSpec, []types.NamespacedName, error) {
	listenerSpec, certSecretKeys, err := l.buildListenerSpec(ctx, lb, gw, port, lbCfg, gwLsCfg, lbLsCfg)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}
	alpnPolicy, err := buildListenerALPNPolicy(listenerSpec.Protocol, lbLsCfg)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}
	listenerSpec.ALPNPolicy = alpnPolicy

	tgTuples, err := l.buildL4TargetGroupTuples(stack, routes, gw, port, listenerSpec.Protocol, lb.Spec.IPAddressType)
	if err != nil {
		return &elbv2model.ListenerSpec{}, nil, err
	}

	if len(tgTuples) == 0 {
		l.logger.Info("Skipping listener creation due to no backend references", "listener", fmt.Sprintf("%v:%v", listenerSpec.Protocol, port), "gateway", k8s.NamespacedName(gw))
		return nil, certSecretKeys, nil
	}
	listenerSpec.DefaultActions = buildL4ListenerDefaultActions(tgTuples, lbLsCfg)
	return listenerSpec, certSecretKeys, nil
}

func (l listenerBuilderImpl) buildL4TargetGroupTuples(stack core.Stack, routes []routeutils.RouteDescriptor, gw *gwv1.Gateway, port int32, listenerProtocol elbv2model.Protocol, ipAddressType elbv2model.IPAddressType) ([]elbv2model.TargetGroupTuple, error) {
	tgTuples := make([]elbv2model.TargetGroupTuple, 0)
	hasNonZeroWeight := false

	descriptorPtr := pickOneL4Route(routes)
	if descriptorPtr != nil && (*descriptorPtr).GetAttachedRules() != nil {
		routeDescriptor := *descriptorPtr
		for _, rule := range routeDescriptor.GetAttachedRules() {
			backends := rule.GetBackends()
			for backendIndx := range backends {
				backend := backends[backendIndx]

				arn, tgErr := l.tgBuilder.buildTargetGroup(stack, gw, port, listenerProtocol, ipAddressType, routeDescriptor, backend)
				if tgErr != nil {
					return tgTuples, tgErr
				}

				tuple := elbv2model.TargetGroupTuple{
					TargetGroupARN: arn,
					Weight:         awssdk.Int32(int32(backend.Weight)),
				}

				if listenerProtocol == elbv2model.ProtocolQUIC || listenerProtocol == elbv2model.ProtocolTCP_QUIC {
					// QUIC protocols don't support specifying weights.
					tuple.Weight = nil
				}

				if backend.Weight > 0 {
					hasNonZeroWeight = true
				}

				tgTuples = append(tgTuples, tuple)
			}
		}
	}
	if len(tgTuples) > 0 && !hasNonZeroWeight {
		l.logger.Info("Skipping listener creation due to all backends having 0 weight", "gateway", k8s.NamespacedName(gw))
		return nil, nil
	}
	return tgTuples, nil
}

func (l listenerBuilderImpl) buildListenerRules(ctx context.Context, stack core.Stack, ls *elbv2model.Listener, ipAddressType elbv2model.IPAddressType, gw *gwv1.Gateway, port int32, routes map[int32][]routeutils.RouteDescriptor) ([]types.NamespacedName, error) {
	// sort all rules based on precedence
	rulesWithPrecedenceOrder := routeutils.SortAllRulesByPrecedence(routes[port], port)
	secrets := make([]types.NamespacedName, 0)
	var albRules []elbv2model.Rule
	for _, ruleWithPrecedence := range rulesWithPrecedenceOrder {
		route := ruleWithPrecedence.CommonRulePrecedence.RouteDescriptor
		rule := ruleWithPrecedence.CommonRulePrecedence.Rule

		// Build Rule Conditions based on GRPCRouteMatch and HTTPRouteMatch
		var conditionsList []elbv2model.RuleCondition
		var err error
		switch route.GetRouteKind() {
		case routeutils.HTTPRouteKind:
			conditionsList, err = routeutils.BuildHttpRuleConditions(ruleWithPrecedence)
		case routeutils.GRPCRouteKind:
			conditionsList, err = routeutils.BuildGrpcRuleConditions(ruleWithPrecedence)
		}
		if err != nil {
			return nil, err
		}

		// Add Rule Conditions based on ListenerRuleConfiguration CRD
		conditionsList = routeutils.BuildSourceIpInCondition(ruleWithPrecedence, conditionsList)

		// set up for building routing actions
		var actions []elbv2model.Action
		var preRoutingAction *elbv2gw.Action
		var routingAction *elbv2gw.Action
		if rule.GetListenerRuleConfig() != nil {
			if ls.Spec.Protocol == elbv2model.ProtocolHTTPS {
				preRoutingAction = getPreRoutingAction(rule.GetListenerRuleConfig())
			}
			routingAction = getRoutingAction(rule.GetListenerRuleConfig())
		}
		targetGroupTuples := make([]elbv2model.TargetGroupTuple, 0, len(rule.GetBackends()))
		for _, backend := range rule.GetBackends() {
			arn, tgErr := l.tgBuilder.buildTargetGroup(stack, gw, port, ls.Spec.Protocol, ipAddressType, route, backend)
			if tgErr != nil {
				return nil, tgErr
			}
			// weighted target group support
			weight := int32(backend.Weight)
			targetGroupTuples = append(targetGroupTuples, elbv2model.TargetGroupTuple{
				TargetGroupARN: arn,
				Weight:         &weight,
			})
		}

		// Build Rule PreRoutingAction
		if preRoutingAction != nil {
			var rulePreRoutingAction *elbv2model.Action
			var secret *types.NamespacedName
			rulePreRoutingAction, secret, err = routeutils.BuildRulePreRoutingAction(ctx, route, preRoutingAction, l.k8sClient, l.secretsManager)
			if err != nil {
				return nil, err
			}
			if secret != nil {
				secrets = append(secrets, *secret)
			}
			if rulePreRoutingAction != nil {
				actions = append(actions, *rulePreRoutingAction)
			}
		}

		// Build Rule Routing Actions
		var ruleRoutingAction *elbv2model.Action
		ruleRoutingAction, err = routeutils.BuildRuleRoutingAction(rule, route, routingAction, targetGroupTuples)
		if err != nil {
			return nil, err
		}

		if ruleRoutingAction == nil {
			l.logger.Info("Filling in no backend actions with fixed 503")
			actions = append(actions, buildL7ListenerNoBackendActions())
		} else {
			actions = append(actions, *ruleRoutingAction)
		}

		tags, tagsErr := l.tagHelper.getListenerRuleTags(rule.GetListenerRuleConfig())
		if tagsErr != nil {
			return nil, tagsErr
		}

		albRules = append(albRules, elbv2model.Rule{
			Conditions: conditionsList,
			Actions:    actions,
			Transforms: routeutils.BuildRoutingRuleTransforms(route, ruleWithPrecedence),
			Tags:       tags,
		})

	}

	priority := int32(1)
	for _, rule := range albRules {
		ruleResID := fmt.Sprintf("%v:%v", port, priority)
		_ = elbv2model.NewListenerRule(stack, ruleResID, elbv2model.ListenerRuleSpec{
			ListenerARN: ls.ListenerARN(),
			Priority:    priority,
			Conditions:  rule.Conditions,
			Actions:     rule.Actions,
			Transforms:  rule.Transforms,
			Tags:        rule.Tags,
		})
		priority += 1
	}
	return secrets, nil
}

func (l listenerBuilderImpl) buildListenerTags(lbCfg elbv2gw.LoadBalancerConfiguration) (map[string]string, error) {
	// We dont have tags at listener level cfg. Hence we add all the load balancer level tags to listeners.
	return l.tagHelper.getLoadBalancerTags(lbCfg)
}

func buildListenerAttributes(lsCfg *elbv2gw.ListenerConfiguration) ([]elbv2model.ListenerAttribute, error) {
	if lsCfg == nil || lsCfg.ListenerAttributes == nil || len(lsCfg.ListenerAttributes) == 0 {
		return []elbv2model.ListenerAttribute{}, nil
	}
	attributes := make([]elbv2model.ListenerAttribute, 0, len(lsCfg.ListenerAttributes))
	for _, attr := range lsCfg.ListenerAttributes {
		attributes = append(attributes, elbv2model.ListenerAttribute{
			Key:   attr.Key,
			Value: attr.Value,
		})
	}
	return attributes, nil
}

func (l listenerBuilderImpl) buildCertificates(ctx context.Context, gw *gwv1.Gateway, port int32, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) ([]elbv2model.Certificate, []types.NamespacedName, error) {
	if !isSecureProtocol(gwLsCfg.protocol) {
		return []elbv2model.Certificate{}, nil, nil
	}
	certs := make([]elbv2model.Certificate, 0)
	// Build explict certs
	if lbLsCfg != nil {
		certs = append(certs, l.buildExplicitTLSCertARNs(ctx, *lbLsCfg)...)
	}
	// If no explicit ARNs were configured, honor the Gateway API's own TLS.CertificateRefs
	// (Secret references) on the listener by importing the referenced secret(s) into ACM.
	var certSecretKeys []types.NamespacedName
	if len(certs) == 0 && len(gwLsCfg.certificateRefs) > 0 {
		refCerts, refSecretKeys, err := l.buildTLSCertARNsFromSecretRefs(ctx, gw, gwLsCfg.certificateRefs)
		if err != nil {
			l.logger.Error(err, fmt.Sprintf("Unable to import TLS certificateRefs for listener on gateway %s with protocol:port %s:%v", k8s.NamespacedName(gw), gwLsCfg.protocol, port))
			return []elbv2model.Certificate{}, nil, err
		}
		certs = append(certs, refCerts...)
		certSecretKeys = refSecretKeys
	}
	// If we still have nothing, fall back to inferred certs using cert discovery
	if len(certs) == 0 {
		if len(gwLsCfg.hostnames) == 0 {
			return []elbv2model.Certificate{}, nil, errors.Errorf("No hostnames found for TLS cert discovery for listener on gateway %s with protocol:port %s:%v", k8s.NamespacedName(gw), gwLsCfg.protocol, port)
		}
		discoveredCerts, err := l.buildInferredTLSCertARNs(ctx, gwLsCfg.hostnames.UnsortedList())
		if err != nil {
			l.logger.Error(err, fmt.Sprintf("Unable to discover certs for listener on gateway %s with protocol:port %s:%v", k8s.NamespacedName(gw), gwLsCfg.protocol, port))
			return []elbv2model.Certificate{}, nil, err
		}
		for _, cert := range discoveredCerts {
			certs = append(certs, elbv2model.Certificate{
				CertificateARN: acmModel.NewExistingCertificate(cert).CertificateARN(),
			})
		}
	}
	return certs, certSecretKeys, nil
}

// buildTLSCertARNsFromSecretRefs resolves a Gateway listener's TLS.CertificateRefs to ACM
// certificate ARNs, importing each referenced Secret into ACM (via certImporter) the first
// time it's seen and reusing the existing import on subsequent reconciles. Returns the
// resolved Secret keys alongside the certificates so callers can register them with
// SecretsManager for watch/GC purposes.
func (l listenerBuilderImpl) buildTLSCertARNsFromSecretRefs(ctx context.Context, gw *gwv1.Gateway, refs []gwv1.SecretObjectReference) ([]elbv2model.Certificate, []types.NamespacedName, error) {
	certificates := make([]elbv2model.Certificate, 0, len(refs))
	secretKeys := make([]types.NamespacedName, 0, len(refs))

	for _, ref := range refs {
		if ref.Group != nil && string(*ref.Group) != certRefCoreAPIGroup {
			return nil, nil, errors.Errorf("unsupported certificateRefs group %q on gateway %s, only the core API group is supported for Secret references", string(*ref.Group), k8s.NamespacedName(gw))
		}
		if ref.Kind != nil && string(*ref.Kind) != certRefSecretKind {
			return nil, nil, errors.Errorf("unsupported certificateRefs kind %q on gateway %s, only %q is supported", string(*ref.Kind), k8s.NamespacedName(gw), certRefSecretKind)
		}

		secretNamespace := gw.Namespace
		if ref.Namespace != nil {
			secretNamespace = string(*ref.Namespace)
		}
		secretKey := types.NamespacedName{Namespace: secretNamespace, Name: string(ref.Name)}

		if secretNamespace != gw.Namespace {
			allowed, err := shared_utils.ValidateCrossNamespaceReference(ctx, l.k8sClient, gw.Namespace, certRefGatewayAPIGroup, certRefGatewayKind, certRefCoreAPIGroup, certRefSecretKind, secretKey.Namespace, secretKey.Name)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "unable to perform reference grant check for certificateRef secret %s", secretKey)
			}
			if !allowed {
				return nil, nil, errors.Errorf("certificateRef secret %s is in a different namespace than gateway %s and no ReferenceGrant permits it", secretKey, k8s.NamespacedName(gw))
			}
		}

		secret, err := l.secretsManager.GetSecret(ctx, l.k8sClient, secretKey)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "unable to fetch certificateRef secret %s", secretKey)
		}

		arn, err := l.certImporter.ImportSecretAsCertificate(ctx, secret)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "unable to import certificateRef secret %s into ACM", secretKey)
		}

		certificates = append(certificates, elbv2model.Certificate{
			CertificateARN: acmModel.NewExistingCertificate(arn).CertificateARN(),
		})
		secretKeys = append(secretKeys, secretKey)
	}

	return certificates, secretKeys, nil
}

func (l listenerBuilderImpl) buildExplicitTLSCertARNs(ctx context.Context, listener elbv2gw.ListenerConfiguration) []elbv2model.Certificate {
	var certs []elbv2model.Certificate
	if listener.DefaultCertificate != nil {
		certs = append(certs, elbv2model.Certificate{
			CertificateARN: acmModel.NewExistingCertificate(*listener.DefaultCertificate).CertificateARN(),
		})
	}

	if listener.Certificates != nil {
		for _, cert := range listener.Certificates {
			certs = append(certs, elbv2model.Certificate{
				CertificateARN: acmModel.NewExistingCertificate(*cert).CertificateARN(),
			})
		}
	}
	return certs
}

func (l listenerBuilderImpl) buildInferredTLSCertARNs(ctx context.Context, hostnames []string) ([]string, error) {
	hosts := sets.NewString()
	for _, hostname := range hostnames {
		hosts.Insert(hostname)
	}

	return l.certDiscovery.Discover(ctx, hosts.List(), nil)
}

// L7 listeners will always have 404 as default actions since we don't have dedicated backend
func buildL7ListenerDefaultActions() []elbv2model.Action {
	action404 := elbv2model.Action{
		Type: elbv2model.ActionTypeFixedResponse,
		FixedResponseConfig: &elbv2model.FixedResponseActionConfig{
			ContentType: awssdk.String("text/plain"),
			StatusCode:  "404",
		},
	}
	return []elbv2model.Action{action404}
}

// returns 500 when no backends are configured
func buildL7ListenerNoBackendActions() elbv2model.Action {
	action500 := elbv2model.Action{
		Type: elbv2model.ActionTypeFixedResponse,
		FixedResponseConfig: &elbv2model.FixedResponseActionConfig{
			ContentType: awssdk.String("text/plain"),
			StatusCode:  "500",
		},
	}
	return action500
}

func buildL4ListenerDefaultActions(tuples []elbv2model.TargetGroupTuple, lbLsCfg *elbv2gw.ListenerConfiguration) []elbv2model.Action {
	var stickyConfig *elbv2model.TargetGroupStickinessConfig
	if lbLsCfg != nil && lbLsCfg.TargetGroupStickiness != nil {
		stickyConfig = &elbv2model.TargetGroupStickinessConfig{}
		stickyConfig.Enabled = lbLsCfg.TargetGroupStickiness
	}

	return []elbv2model.Action{
		{
			Type: elbv2model.ActionTypeForward,
			ForwardConfig: &elbv2model.ForwardActionConfig{
				TargetGroups:                tuples,
				TargetGroupStickinessConfig: stickyConfig,
			},
		},
	}
}

func (l listenerBuilderImpl) buildMutualAuthenticationAttributes(ctx context.Context, gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*elbv2model.MutualAuthenticationAttributes, error) {
	// Skip mTLS configuration for non-secure protocols
	if !isSecureProtocol(gwLsCfg.protocol) || lbLsCfg == nil || lbLsCfg.MutualAuthentication == nil {
		return nil, nil
	}

	mode := string(lbLsCfg.MutualAuthentication.Mode)

	// Process trustStore information for verify mode
	var trustStoreArn *string
	if mode == string(elbv2model.MutualAuthenticationVerifyMode) {
		trustStoreName := awssdk.ToString(lbLsCfg.MutualAuthentication.TrustStore)
		if !strings.HasPrefix(trustStoreName, "arn:") {
			truststoreARNs, err := shared_utils.GetTrustStoreArnFromName(ctx, l.elbv2Client, []string{trustStoreName})
			if err != nil {
				return nil, errors.Wrapf(err, "failed to resolve trustStore ARN for name %s", trustStoreName)
			}
			trustStoreArn = truststoreARNs[trustStoreName]
		} else {
			// Already an ARN, use as-is
			trustStoreArn = awssdk.String(trustStoreName)
		}
	}

	// Initialize with empty default values
	var advertiseTrustStoreCaNames string
	if lbLsCfg.MutualAuthentication.AdvertiseTrustStoreCaNames != nil {
		advertiseTrustStoreCaNames = string(*lbLsCfg.MutualAuthentication.AdvertiseTrustStoreCaNames)
	}

	// Set default ignoreClientCert to false for verify mode if not specified
	ignoreClientCert := lbLsCfg.MutualAuthentication.IgnoreClientCertificateExpiry
	if mode == string(elbv2model.MutualAuthenticationVerifyMode) && ignoreClientCert == nil {
		ignoreClientCert = awssdk.Bool(false)
	}

	// Build the complete mutual authentication configuration
	return &elbv2model.MutualAuthenticationAttributes{
		Mode:                          mode,
		TrustStoreArn:                 trustStoreArn,
		IgnoreClientCertificateExpiry: ignoreClientCert,
		AdvertiseTrustStoreCaNames:    &advertiseTrustStoreCaNames,
	}, nil
}

func (l listenerBuilderImpl) buildSSLPolicy(gwLsCfg gwListenerConfig, lbLsCfg *elbv2gw.ListenerConfiguration) (*string, error) {
	if !isSecureProtocol(gwLsCfg.protocol) {
		return nil, nil
	}
	if lbLsCfg == nil || lbLsCfg.SslPolicy == nil {
		return &l.defaultSSLPolicy, nil
	}
	return lbLsCfg.SslPolicy, nil
}

func isSecureProtocol(protocol elbv2model.Protocol) bool {
	return protocol == elbv2model.ProtocolHTTPS || protocol == elbv2model.ProtocolTLS
}

func buildListenerALPNPolicy(listenerProtocol elbv2model.Protocol, lbLsCfg *elbv2gw.ListenerConfiguration) ([]string, error) {
	if listenerProtocol != elbv2model.ProtocolTLS {
		return nil, nil
	}
	if lbLsCfg == nil || lbLsCfg.ALPNPolicy == nil {
		return []string{string(elbv2gw.ALPNPolicyNone)}, nil
	}
	rawALPNPolicy := *lbLsCfg.ALPNPolicy
	switch rawALPNPolicy {
	case elbv2gw.ALPNPolicyNone, elbv2gw.ALPNPolicyHTTP1Only, elbv2gw.ALPNPolicyHTTP2Only,
		elbv2gw.ALPNPolicyHTTP2Preferred, elbv2gw.ALPNPolicyHTTP2Optional:
		return []string{string(rawALPNPolicy)}, nil
	default:
		return nil, errors.Errorf("invalid ALPN policy %v, policy must be one of [%v, %v, %v, %v, %v]",
			string(rawALPNPolicy), elbv2gw.ALPNPolicyNone, elbv2gw.ALPNPolicyHTTP1Only, elbv2gw.ALPNPolicyHTTP2Only,
			elbv2gw.ALPNPolicyHTTP2Optional, elbv2gw.ALPNPolicyHTTP2Preferred)
	}
}

// mapGatewayListenerConfigsByPort creates a mapping of ports to listener configurations from the Gateway listeners.
func mapGatewayListenerConfigsByPort(listeners []gwv1.Listener, routes map[int32][]routeutils.RouteDescriptor) (map[int32]gwListenerConfig, error) {
	gwListenerConfigs := make(map[int32]gwListenerConfig)
	for _, listener := range listeners {
		port := int32(listener.Port)
		protocol := elbv2model.Protocol(listener.Protocol)

		// The combination of TLS listener + pass through just means to treat this traffic as tcp.
		if protocol == elbv2model.ProtocolTLS {
			if listener.TLS != nil && listener.TLS.Mode != nil && *listener.TLS.Mode == gwv1.TLSModePassthrough {
				protocol = elbv2model.ProtocolTCP
			}
		}

		_, hasPort := gwListenerConfigs[port]
		if !hasPort {
			gwListenerConfigs[port] = gwListenerConfig{
				protocol:  protocol,
				hostnames: sets.New[string](),
			}
		}

		if hasPort && gwListenerConfigs[port].protocol != protocol {
			// Special case TCP_UDP (or TCP_QUIC)

			mergedValue, mergeErr := mergeProtocols(gwListenerConfigs[port].protocol, protocol)

			if mergeErr != nil {
				return nil, fmt.Errorf("invalid listeners on gateway, listeners with same ports cannot have different protocols")
			}

			// TODO this only works for TCP, UDP route merging.
			// If we need to support TLS merging, then this will need
			// to be updated.
			gwListenerConfigs[port] = gwListenerConfig{
				protocol:  mergedValue,
				hostnames: sets.New[string](),
			}
		}

		if listener.Hostname != nil {
			gwListenerConfigs[port].hostnames.Insert(string(*listener.Hostname))
		}

		if isSecureProtocol(protocol) && listener.TLS != nil && len(listener.TLS.CertificateRefs) > 0 {
			cfg := gwListenerConfigs[port]
			cfg.certificateRefs = append(cfg.certificateRefs, listener.TLS.CertificateRefs...)
			gwListenerConfigs[port] = cfg
		}

		listenerRoutes := routes[port]

		if listenerRoutes != nil {
			for _, route := range listenerRoutes {
				// Use compatible hostnames (intersection) instead of raw route hostnames
				compatibleHostnamesByPort := route.GetCompatibleHostnamesByPort()[port]
				if len(compatibleHostnamesByPort) > 0 {
					for _, hostname := range compatibleHostnamesByPort {
						gwListenerConfigs[port].hostnames.Insert(string(hostname))
					}
				} else {
					// Fallback to route hostnames if no compatible hostnames
					for _, routeHostname := range route.GetHostnames() {
						gwListenerConfigs[port].hostnames.Insert(string(routeHostname))
					}
				}
			}
		}

	}
	return gwListenerConfigs, nil
}

// mapLoadBalancerListenerConfigsByPort creates a mapping of ports to their corresponding
// listener configurations from the LoadBalancer configuration.
func mapLoadBalancerListenerConfigsByPort(lbCfg elbv2gw.LoadBalancerConfiguration, gatewayListeners map[int32]gwListenerConfig) map[int32]*elbv2gw.ListenerConfiguration {
	configuredListeners := sets.NewString()

	for port, configuredListener := range gatewayListeners {
		configuredListeners.Insert(generateListenerPortKey(port, configuredListener))
	}

	lbLsCfgs := make(map[int32]*elbv2gw.ListenerConfiguration)
	if lbCfg.Spec.ListenerConfigurations == nil {
		return lbLsCfgs
	}
	for _, lsCfg := range *lbCfg.Spec.ListenerConfigurations {
		lowerValue := strings.ToLower(string(lsCfg.ProtocolPort))
		if configuredListeners.Has(lowerValue) {
			port, _ := strconv.ParseInt(strings.Split(string(lsCfg.ProtocolPort), ":")[1], 10, 64)
			lbLsCfgs[int32(port)] = &lsCfg
		}

	}
	return lbLsCfgs
}

func generateListenerPortKey(port int32, listener gwListenerConfig) string {
	return fmt.Sprintf("%s:%d", strings.ToLower(string(listener.protocol)), port)
}

func newListenerBuilder(loadBalancerType elbv2model.LoadBalancerType, tgBuilder targetGroupBuilder, tagHelper tagHelper, certDiscovery certs.CertDiscovery, certImporter certs.CertImporter, clusterName string, defaultSSLPolicy string, elbv2Client services.ELBV2, k8sClient client.Client, secretsManager k8s.SecretsManager, logger logr.Logger) listenerBuilder {
	return &listenerBuilderImpl{
		elbv2Client:      elbv2Client,
		k8sClient:        k8sClient,
		loadBalancerType: loadBalancerType,
		tgBuilder:        tgBuilder,
		clusterName:      clusterName,
		tagHelper:        tagHelper,
		defaultSSLPolicy: defaultSSLPolicy,
		secretsManager:   secretsManager,
		certDiscovery:    certDiscovery,
		certImporter:     certImporter,
		logger:           logger,
	}
}

// getPreRoutingAction: returns pre routing action for secure listeners from listener rule configuration
// action will only be one of authenticate-oidc, authenticate-cognito, or jwt-validation
func getPreRoutingAction(config *elbv2gw.ListenerRuleConfiguration) *elbv2gw.Action {
	if config != nil && config.Spec.Actions != nil {
		for _, action := range config.Spec.Actions {
			if action.Type == elbv2gw.ActionTypeAuthenticateCognito || action.Type == elbv2gw.ActionTypeAuthenticateOIDC || action.Type == elbv2gw.ActionTypeJwtValidation {
				return &action
			}
		}
	}
	return nil
}

// getRoutingAction: returns routing action from listener rule configuration
// action will only be one of forward, fixed response or redirect
func getRoutingAction(config *elbv2gw.ListenerRuleConfiguration) *elbv2gw.Action {
	if config != nil && config.Spec.Actions != nil {
		for _, action := range config.Spec.Actions {
			if action.Type == elbv2gw.ActionTypeForward || action.Type == elbv2gw.ActionTypeFixedResponse || action.Type == elbv2gw.ActionTypeRedirect {
				return &action
			}
		}
	}
	return nil
}

func mergeProtocols(storedProtocol, proposedProtocol elbv2model.Protocol) (elbv2model.Protocol, error) {
	if storedProtocol == elbv2model.ProtocolTCP_UDP && (proposedProtocol == elbv2model.ProtocolTCP || proposedProtocol == elbv2model.ProtocolUDP) {
		return elbv2model.ProtocolTCP_UDP, nil
	}

	if storedProtocol == elbv2model.ProtocolTCP && proposedProtocol == elbv2model.ProtocolUDP {
		return elbv2model.ProtocolTCP_UDP, nil
	}

	if storedProtocol == elbv2model.ProtocolUDP && proposedProtocol == elbv2model.ProtocolTCP {
		return elbv2model.ProtocolTCP_UDP, nil
	}

	// QUIC protocol merging
	if storedProtocol == elbv2model.ProtocolTCP_QUIC && (proposedProtocol == elbv2model.ProtocolTCP || proposedProtocol == elbv2model.ProtocolQUIC) {
		return elbv2model.ProtocolTCP_QUIC, nil
	}

	if storedProtocol == elbv2model.ProtocolTCP && proposedProtocol == elbv2model.ProtocolQUIC {
		return elbv2model.ProtocolTCP_QUIC, nil
	}

	if storedProtocol == elbv2model.ProtocolQUIC && proposedProtocol == elbv2model.ProtocolTCP {
		return elbv2model.ProtocolTCP_QUIC, nil
	}

	return elbv2model.ProtocolHTTP, errors.New("unsupported merge")
}

// L4 listeners should only allow 1 Route;
/*
		Because a TCP/UDP listener has no mechanism to distinguish between connections (no
		hostname, no SNI, no path), attaching multiple [TCP/UDP]Routes to the same listener
		results in only one route effectively receiving traffic.

		When multiple [TCP/UDP]Routes reference the same listener, the implementation MUST
		follow the general Gateway API route precedence rules defined in `AllowedRoutes`:

		1. The oldest Route based on `metadata.creationTimestamp`.
		2. If timestamps are equal, the Route appearing first in alphabetical order
		   (`namespace/name`).

		All attached [TCP/UDP]Routes are `Accepted`, consistent with how other route types
		handle precedence in the Gateway API. Only the winning route's backends receive
		traffic.


	As we don't support SNI routing, apply this same logic to TLS routes.
*/
func pickOneL4Route(routes []routeutils.RouteDescriptor) *routeutils.RouteDescriptor {
	if len(routes) == 0 {
		return nil
	}
	toReturn := routes[0]
	for _, r := range routes[1:] {
		currentReturnTs := toReturn.GetRouteCreateTimestamp().UnixMilli()
		toCompareTs := r.GetRouteCreateTimestamp().UnixMilli()
		if currentReturnTs > toCompareTs {
			toReturn = r
		} else if currentReturnTs == toCompareTs {
			currentReturnNsn := toReturn.GetRouteNamespacedName()
			toCompareNsn := r.GetRouteNamespacedName()
			if currentReturnNsn.String() > toCompareNsn.String() {
				toReturn = r
			}
		}
	}
	return new(toReturn)
}
