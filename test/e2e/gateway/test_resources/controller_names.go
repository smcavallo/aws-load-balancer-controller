package test_resources

import "os"

// ALBGatewayControllerName and NLBGatewayControllerName are the GatewayClass
// spec.controllerName values the e2e suite uses when creating GatewayClass
// objects. They default to the upstream conventions (gateway.k8s.aws/{alb,nlb})
// and can be overridden via the GATEWAY_ALB_CONTROLLER_NAME and
// GATEWAY_NLB_CONTROLLER_NAME environment variables so downstream forks that
// rebrand the controllerName strings can reuse this suite unchanged.
var (
	ALBGatewayControllerName = envOrDefault("GATEWAY_ALB_CONTROLLER_NAME", "gateway.k8s.aws/alb")
	NLBGatewayControllerName = envOrDefault("GATEWAY_NLB_CONTROLLER_NAME", "gateway.k8s.aws/nlb")
)

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
