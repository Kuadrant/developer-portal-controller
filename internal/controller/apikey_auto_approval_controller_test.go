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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKeyAutoApproval Controller", func() {
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

	Context("When reconciling APIKeyRequest with automatic approval mode", func() {
		var (
			apiProduct    *devportalv1alpha1.APIProduct
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIProduct with automatic approval mode")
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:  "Test API",
					ApprovalMode: "automatic",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  "test-route",
					},
					PublishStatus: "Draft",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating an APIKeyRequest")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespace + "-" + apiKeyName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing automatic approval",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())

			By("Setting the APIKeyRequest status to Pending")
			updatedRequest := &devportalv1alpha1.APIKeyRequest{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyRequest.Name,
				Namespace: apiProductNamespace,
			}, updatedRequest)).To(Succeed())

			meta.SetStatusCondition(&updatedRequest.Status.Conditions, metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionPending,
				Status:             metav1.ConditionTrue,
				Reason:             "Pending",
				Message:            "Awaiting approval",
				ObservedGeneration: updatedRequest.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedRequest)).To(Succeed())
		})

		It("should create automatic approval for pending request", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Waiting for APIKeyRequest status to be set")
			requestKey := types.NamespacedName{
				Name:      apiKeyRequest.Name,
				Namespace: apiProductNamespace,
			}
			Eventually(func() bool {
				fetchedRequest := &devportalv1alpha1.APIKeyRequest{}
				if err := k8sClient.Get(ctx, requestKey, fetchedRequest); err != nil {
					return false
				}
				pendingCondition := meta.FindStatusCondition(fetchedRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				return pendingCondition != nil && pendingCondition.Status == metav1.ConditionTrue
			}, time.Second*5, time.Millisecond*250).Should(BeTrue(), "APIKeyRequest should have Pending condition set")

			By("Running reconciliation for the specific APIKeyRequest")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: requestKey})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyApproval was created")
			approval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyRequest.Name + "-auto",
					Namespace: apiProductNamespace,
				}, approval)
				return err == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying approval has correct fields")
			Expect(approval.Spec.APIKeyRequestRef.Name).To(Equal(apiKeyRequest.Name))
			Expect(approval.Spec.Approved).To(BeTrue())
			Expect(approval.Spec.ReviewedBy).To(Equal("system"))
			Expect(approval.Spec.Reason).To(Equal("AutoApproved"))
			Expect(approval.Spec.Message).To(Equal("Automatically approved based on APIProduct approval mode"))
		})

		It("should be idempotent and not create duplicate approvals", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			requestKey := types.NamespacedName{
				Name:      apiKeyRequest.Name,
				Namespace: apiProductNamespace,
			}

			By("Waiting for APIKeyRequest status to be set")
			Eventually(func() bool {
				fetchedRequest := &devportalv1alpha1.APIKeyRequest{}
				if err := k8sClient.Get(ctx, requestKey, fetchedRequest); err != nil {
					return false
				}
				pendingCondition := meta.FindStatusCondition(fetchedRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				return pendingCondition != nil && pendingCondition.Status == metav1.ConditionTrue
			}, time.Second*5, time.Millisecond*250).Should(BeTrue(), "APIKeyRequest should have Pending condition set")

			By("Running reconciliation first time")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: requestKey})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying approval was created")
			approval := &devportalv1alpha1.APIKeyApproval{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyRequest.Name + "-auto",
					Namespace: apiProductNamespace,
				}, approval)
				return err == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Running reconciliation second time")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: requestKey})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying only one approval exists")
			approvalList := &devportalv1alpha1.APIKeyApprovalList{}
			Expect(k8sClient.List(ctx, approvalList)).To(Succeed())
			Expect(approvalList.Items).To(HaveLen(1), "Should not create duplicate approvals")
		})
	})

	Context("When reconciling APIKeyRequest with manual approval mode", func() {
		var (
			apiProduct    *devportalv1alpha1.APIProduct
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIProduct with manual approval mode")
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:  "Test API",
					ApprovalMode: "manual",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  "test-route",
					},
					PublishStatus: "Draft",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating an APIKeyRequest in pending state")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespace + "-" + apiKeyName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing manual approval",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
				Status: devportalv1alpha1.APIKeyRequestStatus{
					Conditions: []metav1.Condition{
						{
							Type:               devportalv1alpha1.APIKeyConditionPending,
							Status:             metav1.ConditionTrue,
							Reason:             "Pending",
							Message:            "Awaiting approval",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())
			Expect(k8sClient.Status().Update(ctx, apiKeyRequest)).To(Succeed())
		})

		It("should not create automatic approval", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation for the specific APIKeyRequest")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      apiKeyRequest.Name,
					Namespace: apiProductNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no approval was created")
			approvalList := &devportalv1alpha1.APIKeyApprovalList{}
			Expect(k8sClient.List(ctx, approvalList)).To(Succeed())
			Expect(approvalList.Items).To(BeEmpty(), "Should not create approval for manual mode")
		})
	})

	Context("When reconciling APIKeyRequest with missing APIProduct", func() {
		var (
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIKeyRequest referencing non-existent APIProduct")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespace + "-" + apiKeyName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: "non-existent-product",
					},
					PlanTier: "premium",
					UseCase:  "Testing missing product",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
				Status: devportalv1alpha1.APIKeyRequestStatus{
					Conditions: []metav1.Condition{
						{
							Type:               devportalv1alpha1.APIKeyConditionPending,
							Status:             metav1.ConditionTrue,
							Reason:             "Pending",
							Message:            "Awaiting approval",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())
			Expect(k8sClient.Status().Update(ctx, apiKeyRequest)).To(Succeed())
		})

		It("should handle missing APIProduct gracefully", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation for the specific APIKeyRequest")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      apiKeyRequest.Name,
					Namespace: apiProductNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no approval was created")
			approvalList := &devportalv1alpha1.APIKeyApprovalList{}
			Expect(k8sClient.List(ctx, approvalList)).To(Succeed())
			Expect(approvalList.Items).To(BeEmpty(), "Should not create approval when APIProduct is missing")
		})
	})

	Context("When reconciling with APIProduct being deleted", func() {
		var (
			apiProduct    *devportalv1alpha1.APIProduct
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIProduct with automatic approval mode")
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:  "Test API",
					ApprovalMode: "automatic",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  "test-route",
					},
					PublishStatus: "Draft",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating an APIKeyRequest in pending state")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespace + "-" + apiKeyName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing deleted product",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
				Status: devportalv1alpha1.APIKeyRequestStatus{
					Conditions: []metav1.Condition{
						{
							Type:               devportalv1alpha1.APIKeyConditionPending,
							Status:             metav1.ConditionTrue,
							Reason:             "Pending",
							Message:            "Awaiting approval",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())
			Expect(k8sClient.Status().Update(ctx, apiKeyRequest)).To(Succeed())

			By("Marking APIProduct for deletion")
			Expect(k8sClient.Delete(ctx, apiProduct)).To(Succeed())
		})

		It("should not create approval for product being deleted", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation for the specific APIKeyRequest")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      apiKeyRequest.Name,
					Namespace: apiProductNamespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying no approval was created")
			approvalList := &devportalv1alpha1.APIKeyApprovalList{}
			Expect(k8sClient.List(ctx, approvalList)).To(Succeed())
			Expect(approvalList.Items).To(BeEmpty(), "Should not create approval for product being deleted")
		})
	})

	Context("When APIKeyApproval already exists for the request", func() {
		var (
			apiProduct     *devportalv1alpha1.APIProduct
			apiKeyRequest  *devportalv1alpha1.APIKeyRequest
			manualApproval *devportalv1alpha1.APIKeyApproval
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIProduct with automatic approval mode")
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:  "Test API",
					ApprovalMode: "automatic",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  "test-route",
					},
					PublishStatus: "Draft",
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Creating an APIKeyRequest in pending state")
			apiKeyRequest = &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductNamespace + "-" + apiKeyName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing existing approval",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      apiKeyName,
						Namespace: consumerNamespace,
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyRequest)).To(Succeed())

			By("Setting the APIKeyRequest status to Pending")
			updatedRequest := &devportalv1alpha1.APIKeyRequest{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyRequest.Name,
				Namespace: apiProductNamespace,
			}, updatedRequest)).To(Succeed())

			meta.SetStatusCondition(&updatedRequest.Status.Conditions, metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionPending,
				Status:             metav1.ConditionTrue,
				Reason:             "Pending",
				Message:            "Awaiting approval",
				ObservedGeneration: updatedRequest.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedRequest)).To(Succeed())

			By("Creating a manual APIKeyApproval for this request")
			manualApproval = &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyRequest.Name + "-manual",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: apiKeyRequest.Name,
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Reason:     "ManuallyApproved",
					Message:    "Manually approved by admin",
				},
			}
			Expect(k8sClient.Create(ctx, manualApproval)).To(Succeed())
		})

		It("should not create automatic approval when manual approval exists", func() {
			controllerReconciler := &APIKeyAutoApprovalReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			requestKey := types.NamespacedName{
				Name:      apiKeyRequest.Name,
				Namespace: apiProductNamespace,
			}

			By("Waiting for APIKeyRequest status to be set")
			Eventually(func() bool {
				fetchedRequest := &devportalv1alpha1.APIKeyRequest{}
				if err := k8sClient.Get(ctx, requestKey, fetchedRequest); err != nil {
					return false
				}
				pendingCondition := meta.FindStatusCondition(fetchedRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				return pendingCondition != nil && pendingCondition.Status == metav1.ConditionTrue
			}, time.Second*5, time.Millisecond*250).Should(BeTrue(), "APIKeyRequest should have Pending condition set")

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: requestKey})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying only the manual approval exists (no automatic approval created)")
			approvalList := &devportalv1alpha1.APIKeyApprovalList{}
			Expect(k8sClient.List(ctx, approvalList, client.InNamespace(apiProductNamespace))).To(Succeed())
			Expect(approvalList.Items).To(HaveLen(1), "Should have exactly one approval")
			Expect(approvalList.Items[0].Name).To(Equal(manualApproval.Name), "Should be the manual approval")
			Expect(approvalList.Items[0].Spec.ReviewedBy).To(Equal("admin@example.com"), "Should be manually approved")
		})
	})
})
