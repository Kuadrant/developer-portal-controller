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
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod name")
			cmd := exec.Command("kubectl", "get",
				"pods", "-l", "control-plane=controller-manager",
				"-o", "go-template={{ range .items }}"+
					"{{ if not .metadata.deletionTimestamp }}"+
					"{{ .metadata.name }}"+
					"{{ \"\\n\" }}{{ end }}{{ end }}",
				"-n", controllerNamespace,
			)
			podOutput, err := utils.Run(cmd)
			if err != nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get controller pod name: %s\n", err)
				return
			}
			podNames := utils.GetNonEmptyLines(podOutput)
			if len(podNames) == 0 {
				_, _ = fmt.Fprintf(GinkgoWriter, "No controller pod found\n")
				return
			}
			controllerPodName := podNames[0]

			By("Fetching controller manager pod logs")
			cmd = exec.Command("kubectl", "logs", controllerPodName, "-n", controllerNamespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s\n", err)
			}

			By("Fetching Kubernetes events in owner namespace")
			cmd = exec.Command("kubectl", "get", "events", "-n", ownerNamespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Events in %s:\n%s\n", ownerNamespace, eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get events in %s: %s\n", ownerNamespace, err)
			}

			By("Fetching Kubernetes events in consumer namespace")
			cmd = exec.Command("kubectl", "get", "events", "-n", consumerNamespace, "--sort-by=.lastTimestamp")
			eventsOutput, err = utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Events in %s:\n%s\n", consumerNamespace, eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get events in %s: %s\n", consumerNamespace, err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", controllerNamespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Pod description:\n%s\n", podDescription)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to describe controller pod: %s\n", err)
			}
		}
	})

	BeforeAll(func() {
		SetDefaultEventuallyTimeout(2 * time.Minute)
		SetDefaultEventuallyPollingInterval(2 * time.Second)

		By("setting up namespaces and Kuadrant instance")
		SetupNamespacesAndKuadrant(ownerNamespace, consumerNamespace, kuadrantNamespace)
	})

	AfterAll(func() {
		By("cleaning up kuadrant namespace")
		cmd := exec.Command("kubectl", "delete", "ns", kuadrantNamespace, "--wait=false")
		_, _ = utils.Run(cmd)

		By("cleaning up owner namespace")
		cmd = exec.Command("kubectl", "delete", "ns", ownerNamespace, "--wait=false")
		_, _ = utils.Run(cmd)

		By("cleaning up consumer namespace")
		cmd = exec.Command("kubectl", "delete", "ns", consumerNamespace, "--wait=false")
		_, _ = utils.Run(cmd)
	})

	Context("APIKey with automatic approval mode", func() {
		It("should create APIKeyRequest, automatic approval, and approve the APIKey", func() {
			By("creating an HTTPRoute as a reference target")
			httpRouteYAML := fmt.Sprintf(`
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
  namespace: %s
spec:
  parentRefs:
  - name: test-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /api
    backendRefs:
    - name: test-service
      port: 8080
`, ownerNamespace)

			cmd := exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(httpRouteYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create HTTPRoute")

			By("creating an AuthPolicy with API key authentication")
			authPolicyYAML := fmt.Sprintf(`
apiVersion: kuadrant.io/v1
kind: AuthPolicy
metadata:
  name: test-auth-policy
  namespace: %s
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: test-route
  rules:
    authentication:
      "api-key":
        apiKey:
          selector:
            matchLabels:
              kuadrant.io/apikeys: "true"
        credentials:
          authorizationHeader:
            prefix: "API-KEY"
`, ownerNamespace)

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(authPolicyYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create AuthPolicy")

			By("updating AuthPolicy status to Accepted and Enforced")
			authPolicyStatusPatch := `{
				"status": {
					"conditions": [
						{
							"type": "Accepted",
							"status": "True",
							"reason": "Accepted",
							"message": "AuthPolicy has been accepted",
							"lastTransitionTime": "2024-01-01T00:00:00Z"
						},
						{
							"type": "Enforced",
							"status": "True",
							"reason": "Enforced",
							"message": "AuthPolicy has been successfully enforced",
							"lastTransitionTime": "2024-01-01T00:00:00Z"
						}
					]
				}
			}`

			cmd = exec.Command("kubectl", "patch", "authpolicy", "test-auth-policy",
				"-n", ownerNamespace,
				"--type=merge",
				"--subresource=status",
				"-p", authPolicyStatusPatch)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to update AuthPolicy status")

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

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = utils.StringReader(apiProductYAML)
			_, err = utils.Run(cmd)
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
