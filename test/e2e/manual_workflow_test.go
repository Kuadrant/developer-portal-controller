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

var _ = Describe("Manual Approval Workflows", Ordered, func() {
	const (
		ownerNamespace      = "api-owner-manual-test"
		consumerNamespace   = "api-consumer-manual-test"
		kuadrantNamespace   = "kuadrant-manual-ns"
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

		By("creating HTTPRoute and AuthPolicy")
		CreateHTTPRoute(ownerNamespace)
		CreateAuthPolicy(ownerNamespace)
	})

	AfterAll(func() {
		CleanupNamespaces(ownerNamespace, consumerNamespace, kuadrantNamespace)
	})

	testManualApprovalWorkflow := func(apiProductName, apiKeyName string, approved bool, useCase, userID, email string) {
		By("creating an APIProduct with manual approval mode")
		apiProductYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIProduct
metadata:
  name: %s
  namespace: %s
spec:
  displayName: "Manual Test API"
  description: "API Product for testing manual approval/rejection"
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
		Expect(err).NotTo(HaveOccurred(), "Failed to create APIProduct")

		By("verifying APIProduct was created")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apiproduct", apiProductName,
				"-n", ownerNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(apiProductName))
		}).Should(Succeed())

		By("creating a secret with API key in the consumer namespace")
		secretYAML := fmt.Sprintf(`
apiVersion: v1
kind: Secret
metadata:
  name: %s-secret
  namespace: %s
type: Opaque
stringData:
  api_key: test-api-key-value
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
  useCase: "%s"
  requestedBy:
    userId: %s
    email: %s
`, apiKeyName, consumerNamespace, apiProductName, ownerNamespace, apiKeyName, useCase, userID, email)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(apiKeyYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create APIKey")

		By("verifying APIKey was created")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", "jsonpath={.metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal(apiKeyName))
		}).Should(Succeed())

		By("verifying APIKey has Pending condition")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Pending')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "APIKey should have Pending=True condition")
		}).Should(Succeed())

		By("verifying APIKeyRequest was created in the owner namespace")
		var apiKeyRequestName string
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikeyrequest",
				"-n", ownerNamespace,
				"-o", "jsonpath={.items[?(@.spec.apiKeyRef.name=='"+apiKeyName+"')].metadata.name}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).NotTo(BeEmpty(), "APIKeyRequest should be created")
			apiKeyRequestName = output
		}).Should(Succeed())

		By("verifying APIKeyRequest has Pending condition")
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikeyrequest", apiKeyRequestName,
				"-n", ownerNamespace, "-o", "jsonpath={.status.conditions[?(@.type=='Pending')].status}")
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("True"), "APIKeyRequest should have Pending=True condition")
		}).Should(Succeed())

		var approvalReason, expectedCondition string
		if approved {
			approvalReason = "API access approved for testing"
			expectedCondition = "Approved"
		} else {
			approvalReason = "API access denied for testing"
			expectedCondition = "Denied"
		}

		By(fmt.Sprintf("manually creating APIKeyApproval with approved=%v", approved))
		apiKeyApprovalYAML := fmt.Sprintf(`
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyApproval
metadata:
  name: %s-manual
  namespace: %s
spec:
  apiKeyRequestRef:
    name: %s
  approved: %t
  reviewedBy: test-owner
  reviewedAt: "2026-05-25T00:00:00Z"
  reason: "%s"
`, apiKeyRequestName, ownerNamespace, apiKeyRequestName, approved, approvalReason)

		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = utils.StringReader(apiKeyApprovalYAML)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create APIKeyApproval")

		By(fmt.Sprintf("verifying APIKeyRequest gets %s condition", expectedCondition))
		Eventually(func(g Gomega) {
			cmd := exec.Command("kubectl", "get", "apikeyrequest", apiKeyRequestName,
				"-n", ownerNamespace,
				"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", expectedCondition))
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			errMsg := fmt.Sprintf("APIKeyRequest should have %s=True condition", expectedCondition)
			g.Expect(output).To(Equal("True"), errMsg)
		}).Should(Succeed())

		By(fmt.Sprintf("verifying APIKey eventually gets %s condition", expectedCondition))
		Eventually(func(g Gomega) {
			jsonPath := fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", expectedCondition)
			cmd := exec.Command("kubectl", "get", "apikey", apiKeyName,
				"-n", consumerNamespace, "-o", jsonPath)
			output, err := utils.Run(cmd)
			g.Expect(err).NotTo(HaveOccurred())
			errMsg := fmt.Sprintf("APIKey should have %s=True condition", expectedCondition)
			g.Expect(output).To(Equal("True"), errMsg)
		}).Should(Succeed())
	}

	It("should approve an APIKey request", func() {
		testManualApprovalWorkflow(
			"manual-approve-api", "test-manual-apikey",
			true,
			"Testing manual approval flow", "test-user-123", "test@example.com",
		)
	})

	It("should reject an APIKey request", func() {
		testManualApprovalWorkflow(
			"rejection-api", "test-rejection-apikey",
			false,
			"Testing rejection flow", "test-user-456", "test-rejection@example.com",
		)
	})
})
