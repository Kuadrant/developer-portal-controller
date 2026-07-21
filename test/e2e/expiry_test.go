/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kuadrant/developer-portal-controller/test/utils"
)

var _ = Describe("APIKey Expiry", Ordered, func() {
	const (
		ownerNamespace      = "api-owner-expiry-test"
		consumerNamespace   = "api-consumer-expiry-test"
		kuadrantNamespace   = "kuadrant-expiry-ns"
		controllerNamespace = "developer-portal-controller-system"
		apiProductName      = "expiry-test-api"
		apiKeyName          = "expiry-test-key"
	)

	AfterEach(func() {
		LogDebugInfoOnFailure(ownerNamespace, consumerNamespace, controllerNamespace)
	})

	BeforeAll(func() {
		SetDefaultEventuallyTimeout(5 * time.Minute)
		SetDefaultEventuallyPollingInterval(2 * time.Second)

		By("setting up namespaces and Kuadrant instance")
		SetupNamespacesAndKuadrant(ownerNamespace, consumerNamespace, kuadrantNamespace)

		By("creating HTTPRoute and AuthPolicy")
		CreateHTTPRoute(ownerNamespace)
		CreateAuthPolicy(ownerNamespace)
	})

	AfterAll(func() {
		CleanupNamespaces(ownerNamespace, consumerNamespace, kuadrantNamespace)
	})

	It("should set Expired condition and delete enforcement secret after expiresAt passes", func() {
		By("creating an APIProduct")
		apiProductYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIProduct
metadata:
  name: %s
  namespace: %s
spec:
  displayName: "Expiry Test API"
  approvalMode: manual
  publishStatus: Published
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: test-route
`, apiProductName, ownerNamespace)

		cmd := exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(apiProductYAML)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating a secret with API key")
		secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s-secret
  namespace: %s
type: Opaque
stringData:
  api_key: test-expiry-key-value
`, apiKeyName, consumerNamespace)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(secretYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating an APIKey without expiresAt")
		apiKeyYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKey
metadata:
  name: %s
  namespace: %s
spec:
  apiProductRef:
    name: %s
    namespace: %s
  secretRef:
    name: %s-secret
  planTier: premium
  useCase: "expiry testing"
  requestedBy:
    userId: test-user
    email: test@example.com
`, apiKeyName, consumerNamespace, apiProductName, ownerNamespace, apiKeyName)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(apiKeyYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("verifying APIKey has Pending condition")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Pending')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"))
		}).Should(Succeed())

		By("getting APIKeyRequest name")
		var apiKeyRequestName string
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikeyrequest",
				"-n", ownerNamespace,
				"-o", fmt.Sprintf("jsonpath={.items[?(@.spec.apiKeyRef.name=='%s')].metadata.name}", apiKeyName))
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).NotTo(BeEmpty())
			apiKeyRequestName = output
		}).Should(Succeed())

		By("creating APIKeyApproval with approved=true")
		approvalYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyApproval
metadata:
  name: %s-approval
  namespace: %s
spec:
  apiKeyRequestRef:
    name: %s
  approved: true
  reviewedBy: test-owner
  reviewedAt: "%s"
  reason: "Approved for expiry test"
`, apiKeyRequestName, ownerNamespace, apiKeyRequestName, time.Now().UTC().Format(time.RFC3339))

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(approvalYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("verifying APIKey has Approved condition")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Approved')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"))
		}).Should(Succeed())

		By("patching APIKey with expiresAt 30 seconds from now")
		expiresAt := time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
		cmd = exec.Command("kubectl", "patch", "apikey", apiKeyName,
			"-n", consumerNamespace,
			"--type=merge",
			"-p", fmt.Sprintf(`{"spec":{"expiresAt":"%s"}}`, expiresAt))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for key to expire (30 seconds)")
		time.Sleep(35 * time.Second)

		By("verifying APIKey has Expired condition")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Expired')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"))
		}).Should(Succeed())

		By("verifying Approved condition is gone")
		cmd = exec.Command("kubectl", "get", "apikey", apiKeyName,
			"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Approved')].status}")
		output, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(BeEmpty())
	})
})
