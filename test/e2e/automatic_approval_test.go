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

var _ = Describe("Automatic Approval", Ordered, func() {
	const (
		ownerNamespace      = "api-owner-test"
		consumerNamespace   = "api-consumer-test"
		kuadrantNamespace   = "kuadrant-ns"
		apiProductName      = "auto-approve-api"
		apiKeyName          = "test-auto-apikey"
		controllerNamespace = "developer-portal-controller-system"
	)

	AfterEach(func() {
		LogDebugInfoOnFailure(ownerNamespace, consumerNamespace, controllerNamespace)
	})

	BeforeAll(func() {
		SetDefaultEventuallyTimeout(2 * time.Minute)
		SetDefaultEventuallyPollingInterval(2 * time.Second)

		By("setting up namespaces and Kuadrant instance")
		SetupNamespacesAndKuadrant(ownerNamespace, consumerNamespace, kuadrantNamespace)
	})

	AfterAll(func() {
		CleanupNamespaces(ownerNamespace, consumerNamespace, kuadrantNamespace)
	})

	Context("APIKey with automatic approval mode", func() {
		It("should create APIKeyRequest, automatic approval, and approve the APIKey", func() {
			By("creating HTTPRoute and AuthPolicy")
			CreateHTTPRoute(ownerNamespace)
			CreateAuthPolicy(ownerNamespace)

			By("creating an APIProduct with automatic approval mode")
			apiProductYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIProduct
metadata:
  name: %s
  namespace: %s
spec:
  displayName: "Auto Approval Test API"
  description: "API Product for testing automatic approval"
  approvalMode: automatic
  publishStatus: Published
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: test-route
`, apiProductName, ownerNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(apiProductYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create APIProduct")

			By("verifying APIProduct was created")
			verifyAPIProductCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apiproduct", apiProductName,
					"-n", ownerNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(apiProductName))
			}
			Eventually(verifyAPIProductCreated).Should(Succeed())

			By("creating a secret with API key in the consumer namespace")
			secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s-secret
  namespace: %s
type: Opaque
stringData:
  api_key: test-api-key-value-12345
`, apiKeyName, consumerNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(secretYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create secret")

			By("creating an APIKey in the consumer namespace")
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
  useCase: "Testing automatic approval flow"
  requestedBy:
    userId: test-user-123
    email: test@example.com
`, apiKeyName, consumerNamespace, apiProductName, ownerNamespace, apiKeyName)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(apiKeyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create APIKey")

			By("verifying APIKey was created")
			verifyAPIKeyCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
					"-n", consumerNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(apiKeyName))
			}
			Eventually(verifyAPIKeyCreated).Should(Succeed())

			By("verifying APIKeyRequest was created in the owner namespace")
			var apiKeyRequestName string
			verifyAPIKeyRequestCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyrequest",
					"-n", ownerNamespace,
					"-o", "jsonpath={.items[0].metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(BeEmpty(), "APIKeyRequest should be created")
				apiKeyRequestName = output
			}
			Eventually(verifyAPIKeyRequestCreated).Should(Succeed())

			By("verifying APIKeyApproval was automatically created")
			apiKeyApprovalName := fmt.Sprintf("%s-auto", apiKeyRequestName)
			verifyApprovalCreated := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyapproval", apiKeyApprovalName,
					"-n", ownerNamespace, "-o", "jsonpath={.metadata.name}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal(apiKeyApprovalName), "APIKeyApproval should be created with deterministic name")
			}
			Eventually(verifyApprovalCreated).Should(Succeed())

			By("verifying the approval was created by 'system'")
			verifySystemReviewer := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyapproval", apiKeyApprovalName,
					"-n", ownerNamespace, "-o", "jsonpath={.spec.reviewedBy}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("system"), "APIKeyApproval should be reviewed by 'system'")
			}
			Eventually(verifySystemReviewer).Should(Succeed())

			By("verifying the approval is approved")
			verifyApproved := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyapproval", apiKeyApprovalName,
					"-n", ownerNamespace, "-o", "jsonpath={.spec.approved}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("true"), "APIKeyApproval should be approved")
			}
			Eventually(verifyApproved).Should(Succeed())

			By("verifying the approval reason is AutoApproved")
			verifyReason := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyapproval", apiKeyApprovalName,
					"-n", ownerNamespace, "-o", "jsonpath={.spec.reason}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("AutoApproved"), "APIKeyApproval reason should be AutoApproved")
			}
			Eventually(verifyReason).Should(Succeed())

			By("verifying APIKeyRequest gets Approved condition")
			verifyRequestApproved := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikeyrequest", apiKeyRequestName,
					"-n", ownerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Approved')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "APIKeyRequest should have Approved=True condition")
			}
			Eventually(verifyRequestApproved).Should(Succeed())

			By("verifying APIKey eventually gets Approved condition")
			verifyAPIKeyApproved := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
					"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Approved')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "APIKey should have Approved=True condition")
			}
			Eventually(verifyAPIKeyApproved).Should(Succeed())
		})
	})
})
