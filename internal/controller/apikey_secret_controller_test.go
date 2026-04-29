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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	kuadrantv1beta1 "github.com/kuadrant/kuadrant-operator/api/v1beta1"

	devportalv1alpha1 "github.com/kuadrant/developer-portal-controller/api/v1alpha1"
	"github.com/kuadrant/developer-portal-controller/internal/reconcilers"
)

var _ = Describe("APIKeySecret Controller", func() {
	const (
		nodeTimeOut = NodeTimeout(time.Second * 30)
	)
	var (
		consumerNamespace string
		kuadrantNamespace string
		apiKeyName        = "test-apikey"
		apiProductName    = "test-api-product"
		secretName        = "test-secret"
	)

	BeforeEach(func(ctx SpecContext) {
		createNamespaceWithContext(ctx, &consumerNamespace)
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
	})

	AfterEach(func(ctx SpecContext) {
		deleteAPIKeysWithContext(ctx, consumerNamespace)
		deleteKuadrantsWithContext(ctx, kuadrantNamespace)
		deleteNamespaceWithContext(ctx, consumerNamespace)
		deleteNamespaceWithContext(ctx, kuadrantNamespace)
	}, nodeTimeOut)

	Context("When an APIKey is approved", func() {
		var (
			apiKey         *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating consumer secret with API key")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: consumerNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating an APIKey with Approved condition")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing enforcement secret creation",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			By("Setting Approved condition on APIKey")
			apiKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())
		})

		It("should create enforcement secret in kuadrant namespace", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was created")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Verifying enforcement secret has correct labels")
			Expect(enforcementSecret.Labels).To(HaveKeyWithValue(enforcementSecretLabelAPIProduct, apiProductName))
			Expect(enforcementSecret.Labels).To(HaveKeyWithValue(enforcementSecretLabelAPIKey, apiKeyName))
			Expect(enforcementSecret.Labels).To(HaveKeyWithValue(enforcementSecretLabelAPIKeyNamespace, consumerNamespace))
			Expect(enforcementSecret.Labels).To(HaveKeyWithValue(enforcementSecretLabelAuthorinoManagedBy, apiKeySecretLabelAuthorinoValue))

			By("Verifying enforcement secret has correct data")
			Expect(enforcementSecret.Data).To(HaveKey(apiKeySecretKey))
			Expect(string(enforcementSecret.Data[apiKeySecretKey])).To(Equal("test-api-key-value"))
		})

		It("should not duplicate enforcement secret if it already exists", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running first reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was created")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			originalUID := enforcementSecret.UID

			By("Running second reconciliation")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was not recreated")
			Expect(k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)).To(Succeed())
			Expect(enforcementSecret.UID).To(Equal(originalUID))
		})
	})

	Context("When an APIKey is denied", func() {
		var (
			apiKey         *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating consumer secret with API key")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: consumerNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating an APIKey")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing enforcement secret deletion",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		It("should delete enforcement secret when denied", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("First approving the APIKey to create enforcement secret")
			apiKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret exists")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Setting Denied condition on APIKey")
			latestAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: apiKeyName, Namespace: consumerNamespace}, latestAPIKey)).To(Succeed())
			latestAPIKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionDenied,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: latestAPIKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Denied",
					Message:            "API key denied",
				},
			}
			Expect(k8sClient.Status().Update(ctx, latestAPIKey)).To(Succeed())

			By("Running reconciliation after denial")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})
	})

	Context("When APIKey transitions from Approved to Failed", func() {
		var (
			apiKey         *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating consumer secret with API key")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: consumerNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating an APIKey with Approved condition")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing Approved to Failed transition",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			apiKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())
		})

		It("should delete enforcement secret when consumer secret is removed and APIKey transitions to Failed", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Creating enforcement secret for approved APIKey")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret exists")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
			Expect(string(enforcementSecret.Data[apiKeySecretKey])).To(Equal("test-api-key-value"))

			By("Deleting consumer secret (simulating external deletion)")
			Expect(k8sClient.Delete(ctx, consumerSecret)).To(Succeed())

			By("Setting Failed condition on APIKey (simulating status controller detecting missing secret)")
			latestAPIKey := &devportalv1alpha1.APIKey{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: apiKeyName, Namespace: consumerNamespace}, latestAPIKey)).To(Succeed())
			latestAPIKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionFailed,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: latestAPIKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "SecretNotFound",
					Message:            "Consumer secret not found",
				},
			}
			Expect(k8sClient.Status().Update(ctx, latestAPIKey)).To(Succeed())

			By("Running reconciliation after Failed condition is set")
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})
	})

	Context("When consumer secret does not exist", func() {
		var (
			apiKey *devportalv1alpha1.APIKey
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating an APIKey without consumer secret")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: "nonexistent-secret",
					},
					PlanTier: "premium",
					UseCase:  "Testing secret not found",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			By("Setting Approved condition on APIKey")
			apiKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())
		})

		It("should return error when consumer secret not found for approved APIKey", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("consumer secret"))
			Expect(err.Error()).To(ContainSubstring("not found"))
			Expect(err.Error()).To(ContainSubstring("approved APIKey"))

			By("Verifying enforcement secret was not created")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			err = k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("When consumer secret is missing api_key entry", func() {
		var (
			apiKey         *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating consumer secret without api_key entry")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: consumerNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"wrong_key": []byte("test-value"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating an APIKey with Approved condition")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing missing api_key entry",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())

			apiKey.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey)).To(Succeed())
		})

		It("should return error when api_key entry is missing for approved APIKey", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("consumer secret"))
			Expect(err.Error()).To(ContainSubstring("missing"))
			Expect(err.Error()).To(ContainSubstring("api_key"))
			Expect(err.Error()).To(ContainSubstring("approved APIKey"))

			By("Verifying enforcement secret was not created")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			err = k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})
	})

	Context("When APIKey is in Pending state", func() {
		var (
			apiKey         *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
		)

		ctx := context.Background()

		BeforeEach(func() {
			By("Creating consumer secret with API key")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: consumerNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("test-api-key-value"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating an APIKey without conditions (Pending state)")
			apiKey = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: consumerNamespace,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: consumerNamespace,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing pending state",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user",
						Email:  "test@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey)).To(Succeed())
		})

		It("should not create enforcement secret", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret was not created")
			enforcementSecret := &corev1.Secret{}
			enforcementSecretKey := types.NamespacedName{
				Name:      enforcementSecretName(apiKey),
				Namespace: kuadrantNamespace,
			}
			Consistently(func() bool {
				err := k8sClient.Get(ctx, enforcementSecretKey, enforcementSecret)
				return apierrors.IsNotFound(err)
			}, time.Second*2, time.Millisecond*250).Should(BeTrue())
		})
	})

	Context("Enforcement secret naming collision prevention", func() {
		var (
			apiKey1        *devportalv1alpha1.APIKey
			apiKey2        *devportalv1alpha1.APIKey
			consumerSecret *corev1.Secret
			namespace1     string
			namespace2     string
		)

		ctx := context.Background()

		BeforeEach(func() {
			createNamespaceWithContext(ctx, &namespace1)
			createNamespaceWithContext(ctx, &namespace2)

			By("Creating consumer secret in namespace1")
			consumerSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace1,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("namespace1-api-key"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret)).To(Succeed())

			By("Creating consumer secret in namespace2")
			consumerSecret2 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace2,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("namespace2-api-key"),
				},
			}
			Expect(k8sClient.Create(ctx, consumerSecret2)).To(Succeed())

			By("Creating APIKey with same name in namespace1")
			apiKey1 = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: namespace1,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: namespace1,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing collision prevention",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user-1",
						Email:  "test1@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey1)).To(Succeed())

			By("Creating APIKey with same name in namespace2")
			apiKey2 = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      apiKeyName,
					Namespace: namespace2,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: namespace2,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing collision prevention",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "test-user-2",
						Email:  "test2@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey2)).To(Succeed())

			By("Setting Approved condition on both APIKeys")
			apiKey1.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey1.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey1)).To(Succeed())

			apiKey2.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey2.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey2)).To(Succeed())
		})

		AfterEach(func() {
			deleteAPIKeysWithContext(ctx, namespace1)
			deleteAPIKeysWithContext(ctx, namespace2)
			deleteNamespaceWithContext(ctx, namespace1)
			deleteNamespaceWithContext(ctx, namespace2)
		})

		It("should create separate enforcement secrets for APIKeys with same name in different namespaces", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying enforcement secret for namespace1 APIKey")
			enforcementSecret1 := &corev1.Secret{}
			enforcementSecretKey1 := types.NamespacedName{
				Name:      enforcementSecretName(apiKey1),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey1, enforcementSecret1)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
			Expect(string(enforcementSecret1.Data[apiKeySecretKey])).To(Equal("namespace1-api-key"))

			By("Verifying enforcement secret for namespace2 APIKey")
			enforcementSecret2 := &corev1.Secret{}
			enforcementSecretKey2 := types.NamespacedName{
				Name:      enforcementSecretName(apiKey2),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey2, enforcementSecret2)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
			Expect(string(enforcementSecret2.Data[apiKeySecretKey])).To(Equal("namespace2-api-key"))

			By("Verifying secret names are different")
			Expect(enforcementSecret1.Name).NotTo(Equal(enforcementSecret2.Name))
		})
	})

	Context("Enforcement secret naming with ambiguous namespace/name pairs", func() {
		var (
			apiKey1  *devportalv1alpha1.APIKey
			apiKey2  *devportalv1alpha1.APIKey
			nsFooBar string
			nsFoo    string
		)

		ctx := context.Background()

		BeforeEach(func() {
			nsFooBar = "foo-bar"
			nsFoo = "foo"

			By("Creating foo-bar namespace")
			nsObject1 := &corev1.Namespace{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
				ObjectMeta: metav1.ObjectMeta{Name: nsFooBar},
			}
			Expect(k8sClient.Create(ctx, nsObject1)).To(Succeed())

			By("Creating foo namespace")
			nsObject2 := &corev1.Namespace{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"},
				ObjectMeta: metav1.ObjectMeta{Name: nsFoo},
			}
			Expect(k8sClient.Create(ctx, nsObject2)).To(Succeed())

			By("Creating consumer secret in foo-bar namespace")
			secret1 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: nsFooBar,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("foo-bar-baz-key"),
				},
			}
			Expect(k8sClient.Create(ctx, secret1)).To(Succeed())

			By("Creating consumer secret in foo namespace")
			secret2 := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: nsFoo,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					apiKeySecretKey: []byte("foo-bar-baz-key-2"),
				},
			}
			Expect(k8sClient.Create(ctx, secret2)).To(Succeed())

			By("Creating APIKey in foo-bar namespace with name baz")
			apiKey1 = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "baz",
					Namespace: nsFooBar,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: nsFooBar,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing collision: foo-bar/baz",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "collision-test-1",
						Email:  "collision1@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey1)).To(Succeed())

			By("Creating APIKey in foo namespace with name bar-baz")
			apiKey2 = &devportalv1alpha1.APIKey{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bar-baz",
					Namespace: nsFoo,
				},
				Spec: devportalv1alpha1.APIKeySpec{
					APIProductRef: devportalv1alpha1.APIProductReference{
						Name:      apiProductName,
						Namespace: nsFoo,
					},
					SecretRef: corev1.LocalObjectReference{
						Name: secretName,
					},
					PlanTier: "premium",
					UseCase:  "Testing collision: foo/bar-baz",
					RequestedBy: devportalv1alpha1.RequestedBy{
						UserID: "collision-test-2",
						Email:  "collision2@example.com",
					},
				},
			}
			Expect(k8sClient.Create(ctx, apiKey2)).To(Succeed())

			By("Setting Approved condition on both APIKeys")
			apiKey1.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey1.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey1)).To(Succeed())

			apiKey2.Status.Conditions = []metav1.Condition{
				{
					Type:               devportalv1alpha1.APIKeyConditionApproved,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: apiKey2.Generation,
					LastTransitionTime: metav1.Now(),
					Reason:             "Approved",
					Message:            "API key approved",
				},
			}
			Expect(k8sClient.Status().Update(ctx, apiKey2)).To(Succeed())
		})

		AfterEach(func() {
			deleteAPIKeysWithContext(ctx, nsFooBar)
			deleteAPIKeysWithContext(ctx, nsFoo)
			deleteNamespaceWithContext(ctx, nsFooBar)
			deleteNamespaceWithContext(ctx, nsFoo)
		})

		It("should create distinct enforcement secrets for colliding namespace/name pairs", func() {
			controllerReconciler := &APIKeySecretReconciler{
				BaseReconciler: reconcilers.BaseReconciler{
					Client: k8sClient,
					Scheme: k8sClient.Scheme(),
				},
			}

			By("Running reconciliation")
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{})
			Expect(err).NotTo(HaveOccurred())

			By("Fetching enforcement secret for foo-bar/baz APIKey")
			enforcementSecret1 := &corev1.Secret{}
			enforcementSecretKey1 := types.NamespacedName{
				Name:      enforcementSecretName(apiKey1),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey1, enforcementSecret1)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Fetching enforcement secret for foo/bar-baz APIKey")
			enforcementSecret2 := &corev1.Secret{}
			enforcementSecretKey2 := types.NamespacedName{
				Name:      enforcementSecretName(apiKey2),
				Namespace: kuadrantNamespace,
			}
			Eventually(func() error {
				return k8sClient.Get(ctx, enforcementSecretKey2, enforcementSecret2)
			}, time.Second*10, time.Millisecond*250).Should(Succeed())

			By("Verifying enforcement secret names are distinct (EXPECTED TO FAIL with current implementation)")
			Expect(enforcementSecret1.Name).NotTo(Equal(enforcementSecret2.Name),
				"Enforcement secrets for distinct APIKeys (foo-bar/baz and foo/bar-baz) must have different names to avoid collisions")

			By("Verifying each APIKey has its own secret data")
			Expect(string(enforcementSecret1.Data[apiKeySecretKey])).To(Equal("foo-bar-baz-key"),
				"foo-bar/baz should have its own secret data")
			Expect(string(enforcementSecret2.Data[apiKeySecretKey])).To(Equal("foo-bar-baz-key-2"),
				"foo/bar-baz should have its own secret data")
		})
	})
})
