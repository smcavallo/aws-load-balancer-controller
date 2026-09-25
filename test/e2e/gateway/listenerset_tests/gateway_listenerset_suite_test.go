package listenerset_tests

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGatewayListenerSet(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ListenerSet Gateway Suite")
}

var _ = BeforeSuite(func() {
	Expect(InitTF()).To(Succeed())
})
