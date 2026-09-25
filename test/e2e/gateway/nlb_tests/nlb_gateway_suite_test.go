package nlb_tests

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/aws-load-balancer-controller/v3/test/e2e/gateway/alb_tests"
)

func TestNLBGateway(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NLB Gateway Suite")
}

var _ = BeforeSuite(func() {
	Expect(InitTF()).To(Succeed())
	// Init imported package's tf; its Describes are transitively registered here.
	Expect(alb_tests.InitTF()).To(Succeed())
})
