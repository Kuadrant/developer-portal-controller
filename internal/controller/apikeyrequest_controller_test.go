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

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/kuadrant/developer-portal-controller/internal/reconcilers"
)

var _ = Describe("APIKeyRequest Controller", func() {
	const (
		nodeTimeOut = NodeTimeout(time.Second * 30)
	)
	var (
		apiProductNamespace string
		consumerNamespace   string
		apiKeyName          = "test-apikey"
		apiProductName      = "test-api-product"
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &apiProductNamespace)
		createNamespaceWithContext(ctx, &consumerNamespace)
	})

	AfterEach(func(ctx SpecContext) {
		deleteAPIKeysWithContext(ctx, consumerNamespace)
		deleteAPIKeyRequestsWithContext(ctx, apiProductNamespace)
		deleteAPIKeyApprovalsWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, consumerNamespace)
	}, nodeTimeOut)

	Context("When reconciling APIKey resources", func() {
		var (
			apiKey *devportalv1alpha1.APIKey
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIKey in consumer namespace")
			// Ensure namespaces are set
			Expect(apiProductNamespace).NotTo(BeEmpty(), "apiProductNamespace should be set")
			Expect(consumerNamespace).NotTo(BeEmpty(), "consumerNamespace should be set")

			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					PlanTier: "premium",
					UseCase:  "Testing shadow resource creation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		It("should create shadow APIKeyRequest in APIProduct namespace", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest was created in APIProduct namespace")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			apiKeyRequestKey := types.NamespacedName{
				Name:      APIKeyRequestName(apiKey),
				Namespace: apiProductNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, apiKeyRequestKey, apiKeyRequest)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Verifying APIKeyRequest spec fields")
			Expect(apiKeyRequest.Spec.APIProductRef.Name).To(Equal(apiProductName))
			Expect(apiKeyRequest.Spec.PlanTier).To(Equal("premium"))
			Expect(apiKeyRequest.Spec.UseCase).To(Equal("Testing shadow resource creation"))
			Expect(apiKeyRequest.Spec.RequestedBy.UserID).To(Equal("test-user"))
			Expect(apiKeyRequest.Spec.RequestedBy.Email).To(Equal("test@example.com"))
			Expect(apiKeyRequest.Spec.APIKeyRef.Name).To(Equal(apiKeyName))
			Expect(apiKeyRequest.Spec.APIKeyRef.Namespace).To(Equal(consumerNamespace))
		})

		It("should delete APIKeyRequest when APIKey is deleted", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running initial reconciliation to create APIKeyRequest")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest exists")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			apiKeyRequestKey := types.NamespacedName{
				Name:      APIKeyRequestName(apiKey),
				Namespace: apiProductNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, apiKeyRequestKey, apiKeyRequest)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Deleting the APIKey")
			Expect(k8sClient.Delete(ctx, apiKey)).To(Succeed())

			By("Running reconciliation after deletion")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, apiKeyRequestKey, apiKeyRequest)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should update APIKeyRequest when APIKey spec changes", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running initial reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Updating APIKey spec")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			updatedAPIKey.Spec.PlanTier = "enterprise"
			updatedAPIKey.Spec.UseCase = "Updated use case"
			Expect(k8sClient.Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running reconciliation after update")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest spec was updated")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				return apiKeyRequest.Spec.PlanTier == "enterprise" &&
					apiKeyRequest.Spec.UseCase == "Updated use case"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should handle APIKey without cross-namespace APIProductRef", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating an APIKey without cross-namespace ref")
			localAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "local-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name: "local-product",
						// No Namespace specified - should default to same namespace
					},
					PlanTier: "basic",
					UseCase:  "Testing local namespace",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "local-user",
						Email:  "local@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, localAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest was created in same namespace as APIKey")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			apiKeyRequestKey := types.NamespacedName{
				Name:      APIKeyRequestName(localAPIKey),
				Namespace: consumerNamespace, // Should be in the same namespace
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, apiKeyRequestKey, apiKeyRequest)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Verifying APIKeyRequest references the local product")
			Expect(apiKeyRequest.Spec.APIProductRef.Name).To(Equal("local-product"))
		})

		It("should handle multiple APIKeys across namespaces", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating second APIKey")
			secondAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "second-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					PlanTier: "enterprise",
					UseCase:  "Testing multiple keys",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "second-user",
						Email:  "second@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, secondAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying both APIKeyRequests exist")
			firstRequest := &devportalv1alpha1.APIKeyRequest{}
			firstKey := types.NamespacedName{
				Name:      APIKeyRequestName(apiKey),
				Namespace: apiProductNamespace,
			}
			Expect(k8sClient.Get(ctx, firstKey, firstRequest)).To(Succeed())

			secondRequest := &devportalv1alpha1.APIKeyRequest{}
			secondKey := types.NamespacedName{
				Name:      APIKeyRequestName(secondAPIKey),
				Namespace: apiProductNamespace,
			}
			Expect(k8sClient.Get(ctx, secondKey, secondRequest)).To(Succeed())

			By("Verifying each APIKeyRequest has correct spec")
			Expect(firstRequest.Spec.PlanTier).To(Equal("premium"))
			Expect(secondRequest.Spec.PlanTier).To(Equal("enterprise"))
		})

		It("should cleanup orphaned APIKeyRequests", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating an orphaned APIKeyRequest without corresponding APIKey")
			orphanedRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "orphaned-namespace-orphaned-key",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "basic",
					UseCase:  "Orphaned request",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "orphan-user",
						Email:  "orphan@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      "orphaned-key",
						Namespace: "orphaned-namespace",
					},
				},
			}
			Expect(k8sClient.Create(ctx, orphanedRequest)).To(Succeed())

			By("Verifying orphaned request exists")
			orphanKey := types.NamespacedName{
				Name:      "orphaned-namespace-orphaned-key",
				Namespace: apiProductNamespace,
			}
			err := k8sClient.Get(ctx, orphanKey, orphanedRequest)
			Expect(err).NotTo(HaveOccurred())

			By("Running reconciliation")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying orphaned APIKeyRequest was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, orphanKey, orphanedRequest)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should not create shadow resource for Failed APIKeys", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating an APIKey with Failed condition")
			failedAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "failed-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "non-existent-secret",
					},
					PlanTier: "premium",
					UseCase:  "Testing failed state",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, failedAPIKey)).To(Succeed())

			By("Setting Failed condition on the APIKey status")
			Eventually(func(g Gomega) {
				// Get the latest version
				key := &devportalv1alpha1.APIKey{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: "failed-apikey", Namespace: consumerNamespace}, key)
				g.Expect(err).ToNot(HaveOccurred())

				// Set the status
				key.Status.Conditions = []metav1.Condition{
					{
						Type:               devportalv1alpha1.APIKeyConditionFailed,
						Status:             metav1.ConditionTrue,
						ObservedGeneration: key.Generation,
						Reason:             "SecretNotFound",
						Message:            "Referenced secret not found",
						LastTransitionTime: metav1.Now(),
					},
				}

				// Update status
				err = k8sClient.Status().Update(ctx, key)
				g.Expect(err).ToNot(HaveOccurred())
			}, time.Second*5, time.Millisecond*250).Should(Succeed())

			By("Verifying Failed condition is set")
			Eventually(func(g Gomega) {
				key := &devportalv1alpha1.APIKey{}
				err := k8sClient.Get(ctx, client.ObjectKey{Name: "failed-apikey", Namespace: consumerNamespace}, key)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key.Status.Conditions).ToNot(BeEmpty())
				g.Expect(key.Status.Conditions[0].Type).To(Equal(devportalv1alpha1.APIKeyConditionFailed))
				g.Expect(key.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
			}, time.Second*5, time.Millisecond*250).Should(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no shadow APIKeyRequest was created")
			shadowKey := types.NamespacedName{
				Name:      APIKeyRequestName(failedAPIKey),
				Namespace: apiProductNamespace,
			}
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Consistently(func() bool {
				err := k8sClient.Get(ctx, shadowKey, apiKeyRequest)
				return apierrors.IsNotFound(err)
			}, time.Second*2, time.Millisecond*250).Should(BeTrue())
		})

		It("should delete existing shadow resource when APIKey transitions to Failed state", func() {
			controllerReconciler := &APIKeyRequestReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating an APIKey without Failed condition")
			transitionAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "valid-secret",
					},
					PlanTier: "premium",
					UseCase:  "Testing state transition",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionAPIKey)).To(Succeed())

			By("Running reconciliation to create shadow resource")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying shadow APIKeyRequest was created")
			shadowKey := types.NamespacedName{
				Name:      APIKeyRequestName(transitionAPIKey),
				Namespace: apiProductNamespace,
			}
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, shadowKey, apiKeyRequest)
				return err == nil
			}, time.Second*5, time.Millisecond*250).Should(BeTrue())

			By("Updating APIKey to Failed state")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(transitionAPIKey), transitionAPIKey); err != nil {
					return err
				}
				transitionAPIKey.Status.Conditions = []metav1.Condition{
					{
						Type:               devportalv1alpha1.APIKeyConditionFailed,
						Status:             metav1.ConditionTrue,
						ObservedGeneration: transitionAPIKey.Generation,
						Reason:             "SecretNotFound",
						Message:            "Referenced secret not found",
						LastTransitionTime: metav1.Now(),
					},
				}
				return k8sClient.Status().Update(ctx, transitionAPIKey)
			}, time.Second*5, time.Millisecond*100).Should(Succeed())

			By("Running reconciliation after transition to Failed")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying shadow APIKeyRequest was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, shadowKey, apiKeyRequest)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})
	})
})
