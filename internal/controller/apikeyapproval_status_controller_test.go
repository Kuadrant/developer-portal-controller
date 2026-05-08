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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKeyApproval Status Controller", func() {
	const (
		nodeTimeOut = NodeTimeout(time.Second * 30)
	)
	var (
		apiProductNamespace       string
		secondAPIProductNamespace string
		consumerNamespace         string
		apiKeyName                = "test-apikey"
		apiProductName            = "test-api-product"
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &apiProductNamespace)
		createNamespaceWithContext(ctx, &consumerNamespace)
		createNamespaceWithContext(ctx, &secondAPIProductNamespace)
	})

	AfterEach(func(ctx SpecContext) {
		deleteAPIKeysWithContext(ctx, consumerNamespace)
		deleteAPIKeyRequestsWithContext(ctx, apiProductNamespace)
		deleteAPIKeyApprovalsWithContext(ctx, apiProductNamespace)
		deleteAPIKeyRequestsWithContext(ctx, secondAPIProductNamespace)
		deleteAPIKeyApprovalsWithContext(ctx, secondAPIProductNamespace)
		deleteNamespaceWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, secondAPIProductNamespace)
		deleteNamespaceWithContext(ctx, consumerNamespace)
	}, nodeTimeOut)

	Context("When reconciling APIKeyApproval resources", func() {
		var (
			apiKey        *devportalv1alpha1.APIKey
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIKey in consumer namespace")
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
					UseCase:  "Testing APIKeyApproval validation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			By("Creating an APIKeyRequest in apiproduct namespace")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing APIKeyApproval validation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      apiKeyName,
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())
		})

		It("should set Valid=True when APIKeyRequest exists", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval that references the APIKeyRequest")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Approved for production use",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Valid condition is set to True")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "test-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil &&
					validCondition.Status == metav1.ConditionTrue &&
					validCondition.Reason == "Valid"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the message contains the APIKeyRequest reference")
			validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
			Expect(validCondition.Message).To(ContainSubstring(APIKeyRequestName(apiKey)))
		})

		It("should set Valid=False when APIKeyRequest does not exist", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval that references a non-existent APIKeyRequest")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "orphan-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: "non-existent-request",
					},
					Approved:   false,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Reason:     "Invalid request",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Valid condition is set to False")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "orphan-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil &&
					validCondition.Status == metav1.ConditionFalse &&
					validCondition.Reason == "APIKeyRequestNotFound"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the message indicates the APIKeyRequest was not found")
			validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
			Expect(validCondition.Message).To(ContainSubstring("not found"))
			Expect(validCondition.Message).To(ContainSubstring("non-existent-request"))
		})

		It("should not update when status is already in sync", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "sync-test-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Running first reconciliation to sync")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting initial APIKeyApproval state")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      "sync-test-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			initialResourceVersion := updatedApproval.ResourceVersion

			By("Running second reconciliation without changes")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyApproval was not updated")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "sync-test-approval",
				Namespace: apiProductNamespace,
			}, updatedApproval)).To(Succeed())
			// Resource version should be the same if no update occurred
			Expect(updatedApproval.ResourceVersion).To(Equal(initialResourceVersion))
		})

		It("should update when APIKeyRequest becomes available", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval for a non-existent APIKeyRequest")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "late-arrival-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: "late-arrival-request",
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Running reconciliation - should be invalid")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Valid condition is False")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "late-arrival-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil &&
					validCondition.Status == metav1.ConditionFalse &&
					validCondition.Reason == "APIKeyRequestNotFound"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Creating the APIKeyRequest")
			lateRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "late-arrival-request",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "basic",
					UseCase:  "Testing late arrival",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "late-user",
						Email:  "late@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "late-apikey",
					},
				},
			}
			Expect(k8sClient.Create(ctx, lateRequest)).To(Succeed())

			By("Running reconciliation again - should be valid now")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Valid condition is now True")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "late-arrival-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil &&
					validCondition.Status == metav1.ConditionTrue &&
					validCondition.Reason == "Valid"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should update ObservedGeneration when spec changes", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKeyApproval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "generation-test-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying initial ObservedGeneration")
			updatedApproval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "generation-test-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				return updatedApproval.Status.ObservedGeneration == updatedApproval.Generation
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			initialGeneration := updatedApproval.Generation

			By("Updating the APIKeyApproval spec")
			updatedApproval.Spec.Message = "Updated message"
			Expect(k8sClient.Update(ctx, updatedApproval)).To(Succeed())

			By("Running reconciliation again")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying ObservedGeneration was updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "generation-test-approval",
					Namespace: apiProductNamespace,
				}, updatedApproval)
				if err != nil {
					return false
				}
				return updatedApproval.Status.ObservedGeneration == updatedApproval.Generation &&
					updatedApproval.Generation > initialGeneration
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should handle multiple APIKeyApprovals in different namespaces", func() {
			controllerReconciler := &APIKeyApprovalStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating APIKeyApproval in first namespace (valid)")
			approval1 := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-ns-approval-1",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin1@example.com",
					ReviewedAt: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, approval1)).To(Succeed())

			By("Creating APIKeyApproval in second namespace (invalid)")
			approval2 := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "multi-ns-approval-2",
					Namespace: secondAPIProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: "non-existent",
					},
					Approved:   false,
					ReviewedBy: "admin2@example.com",
					ReviewedAt: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, approval2)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying first approval is valid")
			updatedApproval1 := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "multi-ns-approval-1",
					Namespace: apiProductNamespace,
				}, updatedApproval1)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval1.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil && validCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying second approval is invalid")
			updatedApproval2 := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "multi-ns-approval-2",
					Namespace: secondAPIProductNamespace,
				}, updatedApproval2)
				if err != nil {
					return false
				}
				validCondition := meta.FindStatusCondition(updatedApproval2.Status.Conditions, devportalv1alpha1.APIKeyApprovalConditionValid)
				return validCondition != nil && validCondition.Status == metav1.ConditionFalse
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

	})
})
