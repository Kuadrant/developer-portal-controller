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
