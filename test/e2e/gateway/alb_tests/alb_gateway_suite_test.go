package alb_tests

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestALBGateway(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ALB Gateway Suite")
}

var _ = BeforeSuite(func() {
	Expect(InitTF()).To(Succeed())
})
