/*
Copyright 2025.

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

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	ctx       context.Context
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	var err error
	err = devportalv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = planpolicyv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = gwapiv1.Install(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "config", "crd", "bases"),
			filepath.Join("..", "..", "bin", "crd", "gateway-api"),
			filepath.Join("..", "..", "bin", "crd", "kuadrant"),
		},
		ErrorIfCRDPathMissing: true,
	}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}

func createNamespaceWithContext(ctx context.Context, namespace *string) {
	nsObject := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-namespace-"},
	}
	Expect(k8sClient.Create(ctx, nsObject)).ToNot(HaveOccurred())

	*namespace = nsObject.Name
}

func deleteNamespaceWithContext(ctx context.Context, namespace *string) {
	desiredTestNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: *namespace}}

	// First, try to delete the namespace with background propagation to avoid waiting for finalizers
	err := k8sClient.Delete(ctx, desiredTestNamespace, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil && !apierrors.IsNotFound(err) {
		// If delete failed with an error other than NotFound, that's unexpected
		Expect(err).ToNot(HaveOccurred())
	}

	// Then wait for it to be gone or deletion to have started
	Eventually(func(g Gomega) {
		err := k8sClient.Get(ctx, client.ObjectKey{Name: *namespace}, desiredTestNamespace)
		// Accept either NotFound (fully deleted) or DeletionTimestamp set (deletion in progress)
		g.Expect(apierrors.IsNotFound(err) || desiredTestNamespace.DeletionTimestamp != nil).To(BeTrue())
	}).WithContext(ctx).Should(Succeed())
}

func buildBasicGateway(gwName, ns string) *gwapiv1.Gateway {
	return &gwapiv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gwapiv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        gwName,
			Namespace:   ns,
			Annotations: map[string]string{"networking.istio.io/service-type": string(corev1.ServiceTypeClusterIP)},
		},
		Spec: gwapiv1.GatewaySpec{
			GatewayClassName: gwapiv1.ObjectName("my-gateway-class"),
			Listeners: []gwapiv1.Listener{
				{
					Name:     "default",
					Port:     gwapiv1.PortNumber(80),
					Protocol: "HTTP",
				},
			},
		},
	}
}

func buildBasicHttpRoute(routeName, gwName, ns string, hostnames []string) *gwapiv1.HTTPRoute {
	return &gwapiv1.HTTPRoute{
		TypeMeta: metav1.TypeMeta{
			Kind:       "HTTPRoute",
			APIVersion: gwapiv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      routeName,
			Namespace: ns,
		},
		Spec: gwapiv1.HTTPRouteSpec{
			CommonRouteSpec: gwapiv1.CommonRouteSpec{
				ParentRefs: []gwapiv1.ParentReference{
					{
						Name:      gwapiv1.ObjectName(gwName),
						Namespace: ptr.To(gwapiv1.Namespace(ns)),
					},
				},
			},
			Hostnames: lo.Map(hostnames, func(hostname string, _ int) gwapiv1.Hostname { return gwapiv1.Hostname(hostname) }),
			Rules: []gwapiv1.HTTPRouteRule{
				{
					Matches: []gwapiv1.HTTPRouteMatch{
						{
							Path: &gwapiv1.HTTPPathMatch{
								Type:  ptr.To(gwapiv1.PathMatchPathPrefix),
								Value: ptr.To("/toy"),
							},
							Method: ptr.To(gwapiv1.HTTPMethod("GET")),
						},
					},
				},
			},
		},
	}
}

func addAcceptedCondition(route *gwapiv1.HTTPRoute) {
	var conditions []metav1.Condition
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:   string(gwapiv1.RouteConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gwapiv1.RouteReasonAccepted),
	})

	// Create a parent ref from the first parent ref in the route spec
	parentRef := gwapiv1.ParentReference{
		Name: route.Spec.ParentRefs[0].Name,
	}
	// Only include namespace if it was explicitly set and is not empty
	if route.Spec.ParentRefs[0].Namespace != nil && *route.Spec.ParentRefs[0].Namespace != "" {
		parentRef.Namespace = route.Spec.ParentRefs[0].Namespace
	}

	route.Status.Parents = append(route.Status.Parents, gwapiv1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: gwapiv1.GatewayController("example.com/gateway-controller"),
		Conditions:     conditions,
	})
}

func addNotAcceptedCondition(route *gwapiv1.HTTPRoute) {
	var conditions []metav1.Condition
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    string(gwapiv1.RouteConditionAccepted),
		Status:  metav1.ConditionFalse,
		Reason:  "NoMatchingListenerHostname",
		Message: "No matching listener hostname",
	})

	// Create a parent ref from the first parent ref in the route spec
	parentRef := gwapiv1.ParentReference{
		Name: route.Spec.ParentRefs[0].Name,
	}
	// Only include namespace if it was explicitly set and is not empty
	if route.Spec.ParentRefs[0].Namespace != nil && *route.Spec.ParentRefs[0].Namespace != "" {
		parentRef.Namespace = route.Spec.ParentRefs[0].Namespace
	}

	route.Status.Parents = append(route.Status.Parents, gwapiv1.RouteParentStatus{
		ParentRef:      parentRef,
		ControllerName: gwapiv1.GatewayController("example.com/gateway-controller"),
		Conditions:     conditions,
	})
}
