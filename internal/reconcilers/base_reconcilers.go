/*
Copyright 2021 Red Hat, Inc.

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

package reconcilers

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	DeleteTagAnnotation = "kuadrant.io/delete"
)

// TagObjectToDelete adds a special DeleteTagAnnotation to the object's annotations.
// If the object's annotations are nil, it first initializes the Annotations field with an empty map.
func TagObjectToDelete(obj client.Object) {
	// Add custom annotation
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
		obj.SetAnnotations(annotations)
	}
	annotations[DeleteTagAnnotation] = "true"
}

// IsObjectTaggedToDelete checks if the given object is tagged for deletion.
// It looks for the DeleteTagAnnotation in the object's annotations
// and returns true if the annotation value is set to "true", false otherwise.
func IsObjectTaggedToDelete(obj client.Object) bool {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		return false
	}

	annotation, ok := annotations[DeleteTagAnnotation]
	return ok && annotation == "true"
}

// MutateFn is a function which mutates the existing object into it's desired state.
type MutateFn func(existing, desired client.Object) (bool, error)

func CreateOnlyMutator(_, _ client.Object) (bool, error) {
	return false, nil
}

type BaseReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// blank assignment to verify that BaseReconciler implements reconcile.Reconciler
var _ reconcile.Reconciler = &BaseReconciler{}

func NewBaseReconciler(c client.Client, scheme *runtime.Scheme) *BaseReconciler {
	return &BaseReconciler{
		Client: c,
		Scheme: scheme,
	}
}

func (b *BaseReconciler) Reconcile(context.Context, ctrl.Request) (ctrl.Result, error) {
	return reconcile.Result{}, nil
}

// ReconcileResource attempts to mutate the existing state
// in order to match the desired state. The object's desired state must be reconciled
// with the existing state inside the passed in callback MutateFn.
//
// obj: Object of the same type as the 'desired' object.
//
//	Used to read the resource from the kubernetes cluster.
//	Could be zero-valued initialized object.
//
// desired: Object representing the desired state
//
// It returns the object applied to the cluster in the case of updates or an error.
func (b *BaseReconciler) ReconcileResource(ctx context.Context, obj, desired client.Object, mutateFn MutateFn) (client.Object, error) {
	key := client.ObjectKeyFromObject(desired)

	if err := b.Get(ctx, key, obj); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}

		// Not found
		if !IsObjectTaggedToDelete(desired) {
			return nil, b.CreateResource(ctx, desired)
		}

		// Marked for deletion and not found. Nothing to do.
		return nil, nil
	}

	// item found successfully
	if IsObjectTaggedToDelete(desired) {
		return nil, b.DeleteResource(ctx, desired)
	}

	update, err := mutateFn(obj, desired)
	if err != nil {
		return nil, err
	}

	if update {
		if err = b.UpdateResource(ctx, obj); err != nil {
			return nil, err
		}
	}
	return obj, nil
}

func (b *BaseReconciler) GetResource(ctx context.Context, objKey types.NamespacedName, obj client.Object) error {
	logger, _ := logr.FromContext(ctx)
	logger.Info("get object", "kind", strings.Replace(fmt.Sprintf("%T", obj), "*", "", 1), "name", objKey.Name, "namespace", objKey.Namespace)
	return b.Get(ctx, objKey, obj)
}

func (b *BaseReconciler) CreateResource(ctx context.Context, obj client.Object) error {
	logger, _ := logr.FromContext(ctx)
	logger.Info("create object", "kind", strings.Replace(fmt.Sprintf("%T", obj), "*", "", 1), "name", obj.GetName(), "namespace", obj.GetNamespace())
	return b.Create(ctx, obj)
}

func (b *BaseReconciler) UpdateResource(ctx context.Context, obj client.Object) error {
	logger, _ := logr.FromContext(ctx)
	logger.Info("update object", "kind", strings.Replace(fmt.Sprintf("%T", obj), "*", "", 1), "name", obj.GetName(), "namespace", obj.GetNamespace())
	return b.Update(ctx, obj)
}

func (b *BaseReconciler) DeleteResource(ctx context.Context, obj client.Object, options ...client.DeleteOption) error {
	logger, _ := logr.FromContext(ctx)
	logger.Info("delete object", "kind", strings.Replace(fmt.Sprintf("%T", obj), "*", "", 1), "name", obj.GetName(), "namespace", obj.GetNamespace())
	if obj.GetDeletionTimestamp() != nil {
		return nil
	}
	return b.Delete(ctx, obj, options...)
}

func (b *BaseReconciler) UpdateResourceStatus(ctx context.Context, obj client.Object) error {
	logger, _ := logr.FromContext(ctx)
	logger.Info("update object status", "kind", strings.Replace(fmt.Sprintf("%T", obj), "*", "", 1), "name", obj.GetName(), "namespace", obj.GetNamespace())
	return b.Status().Update(ctx, obj)
}
