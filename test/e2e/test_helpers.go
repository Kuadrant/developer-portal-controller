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

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/kuadrant/developer-portal-controller/test/utils"
)

// SetupNamespacesAndKuadrant creates the owner, consumer, and kuadrant namespaces,
// and creates a Kuadrant instance. This is a common setup step for e2e tests.
func SetupNamespacesAndKuadrant(ownerNamespace, consumerNamespace, kuadrantNamespace string) {
	cmd := exec.Command("kubectl", "create", "ns", ownerNamespace)
	_, err := utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create owner namespace")

	cmd = exec.Command("kubectl", "create", "ns", consumerNamespace)
	_, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create consumer namespace")

	cmd = exec.Command("kubectl", "create", "ns", kuadrantNamespace)
	_, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create kuadrant namespace")

	kuadrantYAML := fmt.Sprintf(`
apiVersion: kuadrant.io/v1beta1
kind: Kuadrant
metadata:
  name: kuadrant
  namespace: %s
spec: {}
`, kuadrantNamespace)

	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = utils.StringReader(kuadrantYAML)
	_, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create Kuadrant")
}

// CleanupNamespaces deletes the specified namespaces asynchronously
func CleanupNamespaces(ownerNamespace, consumerNamespace, kuadrantNamespace string) {
	ginkgo.By("cleaning up kuadrant namespace")
	cmd := exec.Command("kubectl", "delete", "ns", kuadrantNamespace, "--wait=false")
	output, err := utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"Failed to delete kuadrant namespace %s: %s", kuadrantNamespace, output)

	ginkgo.By("cleaning up owner namespace")
	cmd = exec.Command("kubectl", "delete", "ns", ownerNamespace, "--wait=false")
	output, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"Failed to delete owner namespace %s: %s", ownerNamespace, output)

	ginkgo.By("cleaning up consumer namespace")
	cmd = exec.Command("kubectl", "delete", "ns", consumerNamespace, "--wait=false")
	output, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(),
		"Failed to delete consumer namespace %s: %s", consumerNamespace, output)
}

// LogDebugInfoOnFailure logs controller logs and events when a test fails
func LogDebugInfoOnFailure(ownerNamespace, consumerNamespace, controllerNamespace string) {
	specReport := ginkgo.CurrentSpecReport()
	if !specReport.Failed() {
		return
	}

	ginkgo.By("Fetching controller manager pod name")
	cmd := exec.Command("kubectl", "get",
		"pods", "-l", "control-plane=controller-manager",
		"-o", "go-template={{ range .items }}"+
			"{{ if not .metadata.deletionTimestamp }}"+
			"{{ .metadata.name }}"+
			"{{ \"\\n\" }}{{ end }}{{ end }}",
		"-n", controllerNamespace,
	)
	podOutput, err := utils.Run(cmd)
	controllerPodName := ""
	if err != nil {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Failed to get controller pod name: %s\n", err)
	} else {
		podNames := utils.GetNonEmptyLines(podOutput)
		if len(podNames) == 0 {
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "No controller pod found\n")
		} else {
			controllerPodName = podNames[0]
		}
	}

	if controllerPodName != "" {
		ginkgo.By("Fetching controller manager pod logs")
		cmd = exec.Command("kubectl", "logs", controllerPodName, "-n", controllerNamespace)
		controllerLogs, err := utils.Run(cmd)
		if err == nil {
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Controller logs:\n%s\n", controllerLogs)
		} else {
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Failed to get Controller logs: %s\n", err)
		}
	}

	ginkgo.By("Fetching Kubernetes events in owner namespace")
	cmd = exec.Command("kubectl", "get", "events", "-n", ownerNamespace, "--sort-by=.lastTimestamp")
	eventsOutput, err := utils.Run(cmd)
	if err == nil {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Events in %s:\n%s\n", ownerNamespace, eventsOutput)
	} else {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Failed to get events in %s: %s\n", ownerNamespace, err)
	}

	ginkgo.By("Fetching Kubernetes events in consumer namespace")
	cmd = exec.Command("kubectl", "get", "events", "-n", consumerNamespace, "--sort-by=.lastTimestamp")
	eventsOutput, err = utils.Run(cmd)
	if err == nil {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Events in %s:\n%s\n", consumerNamespace, eventsOutput)
	} else {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Failed to get events in %s: %s\n", consumerNamespace, err)
	}

	if controllerPodName != "" {
		ginkgo.By("Fetching controller manager pod description")
		cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", controllerNamespace)
		podDescription, err := utils.Run(cmd)
		if err == nil {
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Pod description:\n%s\n", podDescription)
		} else {
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "Failed to describe controller pod: %s\n", err)
		}
	}
}

// CreateHTTPRoute creates an HTTPRoute in the specified namespace
func CreateHTTPRoute(namespace string) {
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
`, namespace)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = utils.StringReader(httpRouteYAML)
	_, err := utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create HTTPRoute")
}

// CreateAuthPolicy creates an AuthPolicy and patches its status to Accepted/Enforced
func CreateAuthPolicy(namespace string) {
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
`, namespace)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = utils.StringReader(authPolicyYAML)
	_, err := utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to create AuthPolicy")

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
		"-n", namespace,
		"--type=merge",
		"--subresource=status",
		"-p", authPolicyStatusPatch)
	_, err = utils.Run(cmd)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "Failed to update AuthPolicy status")
}
