package ports

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestPortsDb(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "IANA Reserved Ports Suite")
}

var _ = Describe("IANA Reserved Ports", func() {
	portsDb, err := NewIanaDB("../data/service-names-port-numbers.csv")
	if err != nil {
		panic(err)
	}

	Context("When the ports db is loaded", func() {
		It("finds well-known ports", func() {
			By("Testing all ports below 1024")
			for port := 0; port <= 1024; port++ {
				Expect(portsDb.IsPortEphemeral(port, TCP)).To(BeFalse())
			}
		})

		It("finds various reserved ports", func() {
			By("Checking commonly used ports above 1024")
			Expect(portsDb.IsPortEphemeral(1080, TCP)).To(BeFalse())  // socks proxy
			Expect(portsDb.IsPortEphemeral(1080, UDP)).To(BeFalse())  // socks proxy
			Expect(portsDb.IsPortEphemeral(3000, TCP)).To(BeFalse())  // nodejs
			Expect(portsDb.IsPortEphemeral(8080, TCP)).To(BeFalse())  // http alternative
			Expect(portsDb.IsPortEphemeral(9443, TCP)).To(BeFalse())  // https alternative
			Expect(portsDb.IsPortEphemeral(27017, TCP)).To(BeFalse()) // mongodb
			Expect(portsDb.IsPortEphemeral(27017, UDP)).To(BeFalse()) // mongodb
		})

		It("does not find true ephemeral ports", func() {
			By("Using ephemeral ports that were used in actual captures")
			ephemeralPorts := []int{37238, 34387, 48510, 37242, 50240, 47264, 49048, 59860}
			for _, port := range ephemeralPorts {
				Expect(portsDb.IsPortEphemeral(port, TCP)).To(BeTrue())
			}
		})
	})
})
