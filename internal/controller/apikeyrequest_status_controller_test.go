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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKeyRequest Status Controller", func() {
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

			By("Creating an APIKeyRequest in apiproduct namespace")

			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing shadow resource creation",
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

		It("should sync conditions from APIKey to APIKeyRequest", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running initial reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Adding a condition to APIKey")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               "Approved",
				Status:             metav1.ConditionTrue,
				Reason:             "Approved",
				Message:            "API key approved",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running reconciliation again")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying condition was synced to APIKeyRequest")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				readyCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, "Approved")
				return readyCondition != nil &&
					readyCondition.Status == metav1.ConditionTrue &&
					readyCondition.Reason == "Approved"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should sync multiple conditions from APIKey to APIKeyRequest", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Adding multiple conditions to APIKey")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               "Approved",
				Status:             metav1.ConditionTrue,
				Reason:             "Approved",
				Message:            "API key approved",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "SecretCreated",
				Message:            "Secret created successfully",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying all conditions were synced to APIKeyRequest")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, "Approved")
				readyCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, "Ready")
				return approvedCondition != nil &&
					approvedCondition.Status == metav1.ConditionTrue &&
					readyCondition != nil &&
					readyCondition.Status == metav1.ConditionTrue &&
					readyCondition.Reason == "SecretCreated"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should update APIKeyRequest when condition status changes", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Setting initial condition on APIKey")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionApproved,
				Status:             metav1.ConditionTrue,
				Reason:             "Approved",
				Message:            "API key request approved by Bob",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying initial condition was synced")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Updating condition on APIKey")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               devportalv1alpha1.APIKeyConditionDenied,
				Status:             metav1.ConditionTrue,
				Reason:             "Denied",
				Message:            "Missing card information",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running reconciliation again")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying condition status was updated")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				deniedCondition := meta.FindStatusCondition(apiKeyRequest.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
				return deniedCondition != nil &&
					deniedCondition.Type == devportalv1alpha1.APIKeyConditionDenied &&
					deniedCondition.Status == metav1.ConditionTrue &&
					deniedCondition.Reason == "Denied"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should skip APIKey marked for deletion", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a new APIKey for deletion test")
			deletionAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "deletion-status-test",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					PlanTier: "premium",
					UseCase:  "Testing deletion skip",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "deletion-user",
						Email:  "deletion@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, deletionAPIKey)).To(Succeed())

			By("Creating corresponding APIKeyRequest")
			deletionAPIKeyRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(deletionAPIKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing deletion skip",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "deletion-user",
						Email:  "deletion@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "deletion-status-test",
					},
				},
			}
			Expect(k8sClient.Create(ctx, deletionAPIKeyRequest)).To(Succeed())

			By("Adding condition to APIKey before deletion")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "deletion-status-test",
				Namespace: consumerNamespace,
			}, deletionAPIKey)).To(Succeed())

			meta.SetStatusCondition(&deletionAPIKey.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Active",
				Message:            "API key is active",
				ObservedGeneration: deletionAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, deletionAPIKey)).To(Succeed())

			By("Marking APIKey for deletion")
			Expect(k8sClient.Delete(ctx, deletionAPIKey)).To(Succeed())

			By("Running reconciliation after deletion")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest status was not updated")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Consistently(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(deletionAPIKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
				if err != nil {
					return false
				}
				// Should have no conditions since we skipped the update
				return len(apiKeyRequest.Status.Conditions) == 0
			}, time.Second*2, time.Millisecond*250).Should(BeTrue())
		})

		It("should not update APIKeyRequest when conditions are already in sync", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Setting initial condition on APIKey")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			meta.SetStatusCondition(&updatedAPIKey.Status.Conditions, metav1.Condition{
				Type:               "Synced",
				Status:             metav1.ConditionTrue,
				Reason:             "InSync",
				Message:            "Conditions are in sync",
				ObservedGeneration: updatedAPIKey.Generation,
			})
			Expect(k8sClient.Status().Update(ctx, updatedAPIKey)).To(Succeed())

			By("Running first reconciliation to sync")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting initial APIKeyRequest state")
			apiKeyRequest := &devportalv1alpha1.APIKeyRequest{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      APIKeyRequestName(apiKey),
					Namespace: apiProductNamespace,
				}, apiKeyRequest)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			initialResourceVersion := apiKeyRequest.ResourceVersion

			By("Running second reconciliation without changes")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIKeyRequest was not updated")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      APIKeyRequestName(apiKey),
				Namespace: apiProductNamespace,
			}, apiKeyRequest)).To(Succeed())
			// Resource version should be the same if no update occurred
			Expect(apiKeyRequest.ResourceVersion).To(Equal(initialResourceVersion))
		})

		It("should handle missing APIKey gracefully", func() {
			controllerReconciler := &APIKeyRequestStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating APIKeyRequest without corresponding APIKey")
			orphanRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "missing-namespace-missing-key",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "basic",
					UseCase:  "Testing missing APIKey",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "missing-user",
						Email:  "missing@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Name:      "missing-key",
						Namespace: "missing-namespace",
					},
				},
			}
			Expect(k8sClient.Create(ctx, orphanRequest)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying reconciliation completed without error")
			// The controller should handle missing APIKey gracefully by skipping it
		})
	})
	It("syncs Pending status after an APIKeyRequest is recreated", func(ctx SpecContext) {
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 k8sClient.Scheme(),
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
		})
		Expect(err).NotTo(HaveOccurred())

		reconciler := &APIKeyRequestStatusReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}
		Expect(reconciler.SetupWithManager(mgr)).To(Succeed())

		managerCtx, stopManager := context.WithCancel(ctx)
		managerDone := make(chan error, 1)
		go func() { managerDone <- mgr.Start(managerCtx) }()
		defer func() {
			stopManager()
			select {
			case err := <-managerDone:
				Expect(err).NotTo(HaveOccurred())
			case <-time.After(5 * time.Second):
				Fail("controller manager did not stop")
			}
		}()
		Expect(mgr.GetCache().WaitForCacheSync(managerCtx)).To(BeTrue())

		apiKey := &devportalv1alpha1.APIKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "recreated-apikey",
				Namespace: consumerNamespace,
			},
			Spec: devportalv1alpha1.APIKeySpec{
				APIProductRef: devportalv1alpha1.APIProductReference{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				PlanTier: "premium",
				UseCase:  "Testing recreated shadow resource",
				RequestedBy: devportalv1alpha1.RequestedBy{
					UserID: "test-user",
					Email:  "test@example.com",
				},
			},
		}
		Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

		request := &devportalv1alpha1.APIKeyRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      APIKeyRequestName(apiKey),
				Namespace: apiProductNamespace,
			},
			Spec: devportalv1alpha1.APIKeyRequestSpec{
				APIProductRef: devportalv1alpha1.LocalAPIProductReference{Name: apiProductName},
				PlanTier:      apiKey.Spec.PlanTier,
				UseCase:       apiKey.Spec.UseCase,
				RequestedBy:   apiKey.Spec.RequestedBy,
				APIKeyRef: devportalv1alpha1.APIKeyReference{
					Name:      apiKey.Name,
					Namespace: apiKey.Namespace,
				},
			},
		}
		Expect(k8sClient.Create(ctx, request)).To(Succeed())

		meta.SetStatusCondition(&apiKey.Status.Conditions, metav1.Condition{
			Type:               devportalv1alpha1.APIKeyConditionPending,
			Status:             metav1.ConditionTrue,
			Reason:             "Pending",
			Message:            "Awaiting approval",
			ObservedGeneration: apiKey.Generation,
		})
		Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())

		requestKey := types.NamespacedName{Name: request.Name, Namespace: request.Namespace}
		hasPending := func() bool {
			current := &devportalv1alpha1.APIKeyRequest{}
			if err := k8sClient.Get(ctx, requestKey, current); err != nil {
				return false
			}
			condition := meta.FindStatusCondition(current.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
			return condition != nil && condition.Status == metav1.ConditionTrue
		}
		Eventually(hasPending, 10*time.Second, 100*time.Millisecond).Should(BeTrue())

		Expect(k8sClient.Delete(ctx, request)).To(Succeed())
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, requestKey, &devportalv1alpha1.APIKeyRequest{}))
		}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())

		replacement := &devportalv1alpha1.APIKeyRequest{
			ObjectMeta: metav1.ObjectMeta{Name: request.Name, Namespace: request.Namespace},
			Spec:       request.Spec,
		}
		Expect(k8sClient.Create(ctx, replacement)).To(Succeed())
		Eventually(hasPending, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
	}, nodeTimeOut)
})
