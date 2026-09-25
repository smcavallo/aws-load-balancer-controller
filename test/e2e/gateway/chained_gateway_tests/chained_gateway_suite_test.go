package chained_gateway_tests

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/aws-load-balancer-controller/v3/test/e2e/gateway/alb_tests"
	"sigs.k8s.io/aws-load-balancer-controller/v3/test/e2e/gateway/nlb_tests"
)

func TestChainedGateway(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chained Gateway Suite")
}

var _ = BeforeSuite(func() {
	Expect(InitTF()).To(Succeed())
	// Init imported packages' tf; their Describes are transitively registered here.
	Expect(alb_tests.InitTF()).To(Succeed())
	Expect(nlb_tests.InitTF()).To(Succeed())
})
