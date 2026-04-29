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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	authorinov1beta3 "github.com/kuadrant/authorino/api/v1beta3"
	kuadrantapiv1 "github.com/kuadrant/kuadrant-operator/api/v1"
	kuadrantv1beta1 "github.com/kuadrant/kuadrant-operator/api/v1beta1"
	planpolicyv1alpha1 "github.com/kuadrant/kuadrant-operator/cmd/extensions/plan-policy/api/v1alpha1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
)

var _ = Describe("APIKey Status Controller", func() {
	const (
		nodeTimeOut = NodeTimeout(time.Second * 30)
	)
	var (
		apiProductNamespace string
		consumerNamespace   string
		secondConsumerNs    string
		kuadrantNamespace   string
		apiKeyName          = "test-apikey"
		apiProductName      = "test-api-product"
		httpRouteName       = "test-route"
		gatewayName         = "test-gateway"
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &kuadrantNamespace)
		// Create Kuadrant CR in kuadrant namespace
		kuadrant := &kuadrantv1beta1.Kuadrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kuadrant",
				Namespace: kuadrantNamespace,
			},
			Spec: kuadrantv1beta1.KuadrantSpec{},
		}
		Expect(k8sClient.Create(ctx, kuadrant)).To(Succeed())

		createNamespaceWithContext(ctx, &apiProductNamespace)
		createNamespaceWithContext(ctx, &consumerNamespace)
		createNamespaceWithContext(ctx, &secondConsumerNs)
	})

	AfterEach(func(ctx SpecContext) {
		deleteAPIKeysWithContext(ctx, consumerNamespace)
		deleteAPIKeysWithContext(ctx, secondConsumerNs)
		deleteAPIKeyRequestsWithContext(ctx, apiProductNamespace)
		deleteAPIKeyApprovalsWithContext(ctx, apiProductNamespace)
		deleteKuadrantsWithContext(ctx, kuadrantNamespace)
		deleteNamespaceWithContext(ctx, apiProductNamespace)
		deleteNamespaceWithContext(ctx, consumerNamespace)
		deleteNamespaceWithContext(ctx, secondConsumerNs)
		deleteNamespaceWithContext(ctx, kuadrantNamespace)
	}, nodeTimeOut)

	Context("When reconciling APIKey status", func() {
		var (
			apiKey        *devportalv1alpha1.APIKey
			apiKeyRequest *devportalv1alpha1.APIKeyRequest
			apiProduct    *devportalv1alpha1.APIProduct
			httpRoute     *gwapiv1.HTTPRoute
			gateway       *gwapiv1.Gateway
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating a Gateway")
			gateway = buildBasicGateway(gatewayName, apiProductNamespace)
			Expect(k8sClient.Create(ctx, gateway)).To(Succeed())

			By("Creating an HTTPRoute")
			httpRoute = buildBasicHttpRoute(httpRouteName, gatewayName, apiProductNamespace, []string{"api.example.com"})
			Expect(k8sClient.Create(ctx, httpRoute)).To(Succeed())
			addAcceptedCondition(httpRoute)
			Expect(k8sClient.Status().Update(ctx, httpRoute)).To(Succeed())

			By("Creating an APIProduct")
			apiProduct = &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiProductName,
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:   "Test API",
					ApprovalMode:  "manual",
					PublishStatus: "Published",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  gwapiv1.ObjectName(httpRouteName),
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiProduct)).To(Succeed())

			By("Setting APIProduct status with discovered plans and auth scheme")
			Eventually(func() error {
				// Refetch to get latest resourceVersion
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(apiProduct), apiProduct); err != nil {
					return err
				}

				premiumLimit := 100
				basicLimit := 10
				apiProduct.Status.DiscoveredPlans = []devportalv1alpha1.PlanSpec{
					{
						Tier: "premium",
						Limits: planpolicyv1alpha1.Limits{
							Daily: &premiumLimit,
						},
					},
					{
						Tier: "basic",
						Limits: planpolicyv1alpha1.Limits{
							Daily: &basicLimit,
						},
					},
				}
				apiProduct.Status.DiscoveredAuthScheme = &kuadrantapiv1.AuthSchemeSpec{
					Authentication: map[string]kuadrantapiv1.MergeableAuthenticationSpec{
						"api-key": {
							AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
								Credentials: authorinov1beta3.Credentials{
									AuthorizationHeader: &authorinov1beta3.Prefixed{
										Prefix: "Bearer",
									},
								},
								AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
									ApiKey: &authorinov1beta3.ApiKeyAuthenticationSpec{
										Selector: &metav1.LabelSelector{
											MatchLabels: map[string]string{"app": "test"},
										},
									},
								},
							},
						},
					},
				}
				return k8sClient.Status().Update(ctx, apiProduct)
			}, time.Second*5, time.Millisecond*100).Should(Succeed())

			By("Creating an APIKey in consumer namespace")
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
					UseCase:  "Testing APIKey status",
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
					UseCase:  "Testing APIKey status",
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

		It("should set Failed condition when APIProduct does not exist", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKey that references a non-existent APIProduct")
			orphanAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "orphan-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      "non-existent-product",
						Namespace: apiProductNamespace,
					},
					PlanTier: "premium",
					UseCase:  "Testing failure",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, orphanAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "orphan-apikey",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				g.Expect(failedCondition).NotTo(BeNil())
				g.Expect(failedCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(failedCondition.Reason).To(Equal("APIProductNotFound"))
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})

		It("should set Failed condition when Secret does not exist", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKey that references a non-existent Secret")
			apiKeyWithMissingSecret := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apikey-missing-secret",
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
					UseCase:  "Testing secret validation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyWithMissingSecret)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set with SecretNotFound reason")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "apikey-missing-secret",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)

				g.Expect(failedCondition).NotTo(BeNil())
				g.Expect(failedCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(failedCondition.Reason).To(Equal("SecretNotFound"))
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})

		It("should set Pending condition when no approval exists", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Pending condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())
				pendingCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				g.Expect(pendingCondition).NotTo(BeNil())
				g.Expect(pendingCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(pendingCondition.Reason).To(Equal("AwaitingApproval"))

				// No other conditions should be present
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				g.Expect(approvedCondition).To(BeNil())
				deniedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
				g.Expect(deniedCondition).To(BeNil())
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				g.Expect(failedCondition).To(BeNil())
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})

		It("should set Failed condition when Secret does not have api_key entry", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a Secret without api_key entry")
			secretWithoutAPIKey := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-without-apikey",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"some_other_key": []byte("some-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secretWithoutAPIKey)).To(Succeed())

			By("Creating an APIKey that references the Secret without api_key")
			apiKeyWithInvalidSecret := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apikey-invalid-secret",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "secret-without-apikey",
					},
					PlanTier: "premium",
					UseCase:  "Testing secret validation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKeyWithInvalidSecret)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set with SecretAPIKeyNotFound reason")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "apikey-invalid-secret",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				return failedCondition != nil &&
					failedCondition.Status == metav1.ConditionTrue &&
					failedCondition.Reason == "SecretAPIKeyNotFound"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should transition from Pending to Approved when approval is granted", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running initial reconciliation to set Pending state")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying initial Pending condition")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				pendingCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				return pendingCondition != nil && pendingCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Creating an approval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Approved",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation after approval")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying transition to Approved and Pending removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				pendingCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				return approvedCondition != nil &&
					approvedCondition.Status == metav1.ConditionTrue &&
					pendingCondition == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should set Approved condition when valid approval exists", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a valid APIKeyApproval")
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
					Message:    "Approved for production",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			// Set Valid condition on the approval
			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Approved condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return approvedCondition != nil &&
					approvedCondition.Status == metav1.ConditionTrue &&
					approvedCondition.Reason == "Approved"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the message contains reviewer and custom message")
			approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
			Expect(approvedCondition.Message).To(ContainSubstring("admin@example.com"))
			Expect(approvedCondition.Message).To(ContainSubstring("Approved for production"))
		})

		It("should set Denied condition when denial exists", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a denial APIKeyApproval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-denial",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(apiKey),
					},
					Approved:   false,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Reason:     "Insufficient justification",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			// Set Valid condition on the approval
			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Denied condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				deniedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
				return deniedCondition != nil &&
					deniedCondition.Status == metav1.ConditionTrue &&
					deniedCondition.Reason == "Denied"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying the message contains reviewer and reason")
			deniedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
			Expect(deniedCondition.Message).To(ContainSubstring("admin@example.com"))
			Expect(deniedCondition.Message).To(ContainSubstring("Insufficient justification"))
		})

		It("should ignore invalid APIKeyApprovals", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an invalid APIKeyApproval (without Valid condition)")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "invalid-approval",
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

			// Set Valid=False on the approval
			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionFalse,
					ObservedGeneration: approval.Generation,
					Reason:             "APIKeyRequestNotFound",
					Message:            "Invalid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Pending condition is set (invalid approval is ignored)")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())

				pendingCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionPending)
				g.Expect(pendingCondition).NotTo(BeNil())
				g.Expect(pendingCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(pendingCondition.Reason).To(Equal("AwaitingApproval"))

				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				g.Expect(approvedCondition).To(BeNil())
				deniedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
				g.Expect(deniedCondition).To(BeNil())
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})

		It("should populate APIHostname from HTTPRoute", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIHostname is populated")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				return updatedAPIKey.Status.APIHostname == "api.example.com"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should populate plan limits from APIProduct", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Limits are populated for premium plan")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				if updatedAPIKey.Status.Limits == nil {
					return false
				}
				return updatedAPIKey.Status.Limits.Daily != nil && *updatedAPIKey.Status.Limits.Daily == 100
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should populate AuthScheme from APIProduct", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying AuthScheme is populated")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				return updatedAPIKey.Status.AuthScheme != nil &&
					updatedAPIKey.Status.AuthScheme.Credentials != nil &&
					updatedAPIKey.Status.AuthScheme.Credentials.AuthorizationHeader != nil &&
					updatedAPIKey.Status.AuthScheme.Credentials.AuthorizationHeader.Prefix == "Bearer"
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should set ObservedGeneration", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying ObservedGeneration is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				return updatedAPIKey.Status.ObservedGeneration == updatedAPIKey.Generation
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should not update status when already in sync", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Running first reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting initial state")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, updatedAPIKey)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			initialResourceVersion := updatedAPIKey.ResourceVersion

			By("Running second reconciliation without changes")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying status was not updated")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      apiKeyName,
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())
			Expect(updatedAPIKey.ResourceVersion).To(Equal(initialResourceVersion))
		})

		It("should handle multiple APIKeys in different namespaces", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKey in second namespace")
			secondAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "second-apikey",
					Namespace: secondConsumerNs,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					PlanTier: "basic",
					UseCase:  "Testing multi-namespace",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "user2",
						Email:  "user2@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, secondAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying both APIKeys have status updated")
			firstAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				}, firstAPIKey)
				return err == nil && firstAPIKey.Status.ObservedGeneration == firstAPIKey.Generation
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			updatedSecondAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "second-apikey",
					Namespace: secondConsumerNs,
				}, updatedSecondAPIKey)
				if err != nil {
					return false
				}
				// Verify basic plan limits (10 daily)
				if updatedSecondAPIKey.Status.Limits == nil {
					return false
				}
				return updatedSecondAPIKey.Status.Limits.Daily != nil && *updatedSecondAPIKey.Status.Limits.Daily == 10
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should handle HTTPRoute without hostnames", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an HTTPRoute without hostnames")
			noHostRoute := &gwapiv1.HTTPRoute{
				TypeMeta: metav1.TypeMeta{
					Kind:       "HTTPRoute",
					APIVersion: gwapiv1.GroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-host-route",
					Namespace: apiProductNamespace,
				},
				Spec: gwapiv1.HTTPRouteSpec{
					CommonRouteSpec: gwapiv1.CommonRouteSpec{
						ParentRefs: []gwapiv1.ParentReference{
							{
								Name:      gwapiv1.ObjectName(gatewayName),
								Namespace: ptr.To(gwapiv1.Namespace(apiProductNamespace)),
							},
						},
					},
					Hostnames: []gwapiv1.Hostname{}, // Empty hostnames
				},
			}
			Expect(k8sClient.Create(ctx, noHostRoute)).To(Succeed())

			By("Creating APIProduct targeting the route without hostnames")
			noHostProduct := &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-host-product",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:   "No Host API",
					ApprovalMode:  "manual",
					PublishStatus: "Published",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  gwapiv1.ObjectName("no-host-route"),
					},
				},
			}
			Expect(k8sClient.Create(ctx, noHostProduct)).To(Succeed())

			By("Creating APIKey for the product")
			noHostAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-host-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      "no-host-product",
						Namespace: apiProductNamespace,
					},
					PlanTier: "premium",
					UseCase:  "Testing no hostname",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, noHostAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying APIHostname is empty")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "no-host-apikey",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				return err == nil && updatedAPIKey.Status.APIHostname == ""
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should transition from Failed to Approved state", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIKey that initially references a non-existent Secret")
			transitionAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-failed-to-approved",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "initially-missing-secret",
					},
					PlanTier: "premium",
					UseCase:  "Testing transition",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionAPIKey)).To(Succeed())

			By("Creating APIKeyRequest for the APIKey")
			transitionRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(transitionAPIKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing transition",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "transition-failed-to-approved",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionRequest)).To(Succeed())

			By("Running reconciliation to set Failed condition")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-failed-to-approved",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				return failedCondition != nil && failedCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Creating the Secret to resolve the failure")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "initially-missing-secret",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an approval for the APIKey")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(transitionAPIKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Approved after fixing issues",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation to transition to Approved state")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Approved condition is set and Failed condition is removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-failed-to-approved",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				return approvedCondition != nil &&
					approvedCondition.Status == metav1.ConditionTrue &&
					failedCondition == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should transition to Failed state and clear other conditions", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a valid Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-to-be-deleted",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an APIKey with valid references")
			transitionAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-to-failed",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "secret-to-be-deleted",
					},
					PlanTier: "premium",
					UseCase:  "Testing transition to failed",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionAPIKey)).To(Succeed())

			By("Creating APIKeyRequest")
			transitionRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(transitionAPIKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing transition to failed",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "transition-to-failed",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionRequest)).To(Succeed())

			By("Creating an approval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "approval-before-failure",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(transitionAPIKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Initially approved",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation to set Approved condition")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Approved condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-to-failed",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Deleting the Secret to trigger failure")
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())

			By("Running reconciliation to transition to Failed state")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set and Approved condition is removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-to-failed",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return failedCondition != nil &&
					failedCondition.Status == metav1.ConditionTrue &&
					approvedCondition == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should transition to Denied state and clear other conditions", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a valid Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-for-denied",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an APIKey")
			transitionAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "transition-to-denied",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "secret-for-denied",
					},
					PlanTier: "premium",
					UseCase:  "Testing transition to denied",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionAPIKey)).To(Succeed())

			By("Creating APIKeyRequest")
			transitionRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(transitionAPIKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing transition to denied",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "transition-to-denied",
					},
				},
			}
			Expect(k8sClient.Create(ctx, transitionRequest)).To(Succeed())

			By("Creating an initial approval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "approval-before-denial",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(transitionAPIKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Initially approved",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running reconciliation to set Approved condition")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Approved condition is set")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-to-denied",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Deleting the approval and creating a denial")
			Expect(k8sClient.Delete(ctx, approval)).To(Succeed())

			denial := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "denial-decision",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(transitionAPIKey),
					},
					Approved:   false,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Reason:     "Policy violation",
				},
			}
			Expect(k8sClient.Create(ctx, denial)).To(Succeed())

			denial.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: denial.Generation,
					Reason:             "Valid",
					Message:            "Valid denial",
					LastTransitionTime: metav1.Now(),
				},
			}
			denial.Status.ObservedGeneration = denial.Generation
			Expect(k8sClient.Status().Update(ctx, denial)).To(Succeed())

			By("Running reconciliation to transition to Denied state")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Denied condition is set and Approved condition is removed")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "transition-to-denied",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				deniedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionDenied)
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				return deniedCondition != nil &&
					deniedCondition.Status == metav1.ConditionTrue &&
					approvedCondition == nil
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should not update condition timestamp when state remains unchanged", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating a valid Secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "secret-stable-state",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			By("Creating an APIKey")
			stableAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "stable-state-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "secret-stable-state",
					},
					PlanTier: "premium",
					UseCase:  "Testing stable state",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, stableAPIKey)).To(Succeed())

			By("Creating APIKeyRequest")
			stableRequest := &devportalv1alpha1.APIKeyRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      APIKeyRequestName(stableAPIKey),
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyRequestSpec{
					APIProductRef: devportalv1alpha1.LocalAPIProductReference{
						Name: apiProductName,
					},
					PlanTier: "premium",
					UseCase:  "Testing stable state",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
					APIKeyRef: devportalv1alpha1.APIKeyReference{
						Namespace: consumerNamespace,
						Name:      "stable-state-apikey",
					},
				},
			}
			Expect(k8sClient.Create(ctx, stableRequest)).To(Succeed())

			By("Creating an approval")
			approval := &devportalv1alpha1.APIKeyApproval{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "stable-approval",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIKeyApprovalSpec{
					APIKeyRequestRef: devportalv1alpha1.APIKeyRequestReference{
						Name: APIKeyRequestName(stableAPIKey),
					},
					Approved:   true,
					ReviewedBy: "admin@example.com",
					ReviewedAt: metav1.Now(),
					Message:    "Approved",
				},
			}
			Expect(k8sClient.Create(ctx, approval)).To(Succeed())

			approval.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyApprovalConditionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: approval.Generation,
					Reason:             "Valid",
					Message:            "Valid approval",
					LastTransitionTime: metav1.Now(),
				},
			}
			approval.Status.ObservedGeneration = approval.Generation
			Expect(k8sClient.Status().Update(ctx, approval)).To(Succeed())

			By("Running first reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Getting the initial Approved condition timestamp")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			var initialTimestamp metav1.Time
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "stable-state-apikey",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				if err != nil {
					return false
				}
				approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
				if approvedCondition != nil && approvedCondition.Status == metav1.ConditionTrue {
					initialTimestamp = approvedCondition.LastTransitionTime
					return true
				}
				return false
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Waiting a moment to ensure timestamps would differ if updated")
			time.Sleep(time.Millisecond * 100)

			By("Running second reconciliation without any changes")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying the Approved condition timestamp has not changed")
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      "stable-state-apikey",
				Namespace: consumerNamespace,
			}, updatedAPIKey)).To(Succeed())

			approvedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionApproved)
			Expect(approvedCondition).NotTo(BeNil())
			Expect(approvedCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(approvedCondition.LastTransitionTime).To(Equal(initialTimestamp))
		})

		It("should set Failed condition when APIProduct has no API key authentication scheme", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIProduct without API key authentication scheme")
			noAuthProduct := &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-auth-product",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:   "No Auth API",
					ApprovalMode:  "manual",
					PublishStatus: "Published",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  gwapiv1.ObjectName(httpRouteName),
					},
				},
			}
			Expect(k8sClient.Create(ctx, noAuthProduct)).To(Succeed())

			By("Setting APIProduct status with discovered plans but without API key auth scheme")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(noAuthProduct), noAuthProduct); err != nil {
					return err
				}

				basicLimit := 10
				noAuthProduct.Status.DiscoveredPlans = []devportalv1alpha1.PlanSpec{
					{
						Tier: "basic",
						Limits: planpolicyv1alpha1.Limits{
							Daily: &basicLimit,
						},
					},
				}
				// Set DiscoveredAuthScheme with JWT authentication (no API key)
				noAuthProduct.Status.DiscoveredAuthScheme = &kuadrantapiv1.AuthSchemeSpec{
					Authentication: map[string]kuadrantapiv1.MergeableAuthenticationSpec{
						"oidc": {
							AuthenticationSpec: authorinov1beta3.AuthenticationSpec{
								AuthenticationMethodSpec: authorinov1beta3.AuthenticationMethodSpec{
									Jwt: &authorinov1beta3.JwtAuthenticationSpec{
										IssuerUrl: "https://example.com",
									},
								},
							},
						},
					},
				}
				return k8sClient.Status().Update(ctx, noAuthProduct)
			}, time.Second*5, time.Millisecond*100).Should(Succeed())

			By("Creating a Secret for the APIKey")
			noAuthSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-auth-secret",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, noAuthSecret)).To(Succeed())

			By("Creating an APIKey that references the APIProduct without API key auth")
			noAuthAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-auth-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      "no-auth-product",
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "no-auth-secret",
					},
					PlanTier: "basic",
					UseCase:  "Testing no auth scheme",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, noAuthAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set with APIKeyAuthSchemeNotFound reason")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "no-auth-apikey",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				g.Expect(failedCondition).NotTo(BeNil())
				g.Expect(failedCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(failedCondition.Reason).To(Equal("APIKeyAuthSchemeNotFound"))
				g.Expect(failedCondition.Message).To(ContainSubstring("does not have an API key authentication scheme configured"))
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})

		It("should set Failed condition when APIProduct has no DiscoveredAuthScheme at all", func() {
			controllerReconciler := &APIKeyStatusReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			By("Creating an APIProduct without any DiscoveredAuthScheme")
			noSchemeProduct := &devportalv1alpha1.APIProduct{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-scheme-product",
					Namespace: apiProductNamespace,
				},
				Spec: devportalv1alpha1.APIProductSpec{
					DisplayName:   "No Scheme API",
					ApprovalMode:  "manual",
					PublishStatus: "Published",
					TargetRef: gatewayapiv1alpha2.LocalPolicyTargetReference{
						Group: gwapiv1.GroupName,
						Kind:  "HTTPRoute",
						Name:  gwapiv1.ObjectName(httpRouteName),
					},
				},
			}
			Expect(k8sClient.Create(ctx, noSchemeProduct)).To(Succeed())

			By("Setting APIProduct status with discovered plans but NO DiscoveredAuthScheme")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(noSchemeProduct), noSchemeProduct); err != nil {
					return err
				}

				basicLimit := 10
				noSchemeProduct.Status.DiscoveredPlans = []devportalv1alpha1.PlanSpec{
					{
						Tier: "basic",
						Limits: planpolicyv1alpha1.Limits{
							Daily: &basicLimit,
						},
					},
				}
				noSchemeProduct.Status.DiscoveredAuthScheme = nil
				return k8sClient.Status().Update(ctx, noSchemeProduct)
			}, time.Second*5, time.Millisecond*100).Should(Succeed())

			By("Creating a Secret for the APIKey")
			noSchemeSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-scheme-secret",
					Namespace: consumerNamespace,
				},
				Data: map[string][]byte{
					"api_key": []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, noSchemeSecret)).To(Succeed())

			By("Creating an APIKey that references the APIProduct without DiscoveredAuthScheme")
			noSchemeAPIKey := &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-scheme-apikey",
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      "no-scheme-product",
						Namespace: apiProductNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "no-scheme-secret",
					},
					PlanTier: "basic",
					UseCase:  "Testing no discovered auth scheme",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, noSchemeAPIKey)).To(Succeed())

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying Failed condition is set with AuthSchemeNotFound reason")
			updatedAPIKey := &devportalv1alpha1.APIKey{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      "no-scheme-apikey",
					Namespace: consumerNamespace,
				}, updatedAPIKey)
				g.Expect(err).NotTo(HaveOccurred())
				failedCondition := meta.FindStatusCondition(updatedAPIKey.Status.Conditions, devportalv1alpha1.APIKeyConditionFailed)
				g.Expect(failedCondition).NotTo(BeNil())
				g.Expect(failedCondition.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(failedCondition.Reason).To(Equal("AuthSchemeNotFound"))
				g.Expect(failedCondition.Message).To(ContainSubstring("does not have a discovered authentication scheme"))
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})
	})
})
