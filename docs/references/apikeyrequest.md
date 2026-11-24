# The APIKeyRequest Custom Resource Definition (CRD)

## Overview

The APIKeyRequest CRD is part of the Developer Portal extension for Kuadrant. It is a shadow resource that mirrors an APIKey in the API owner's namespace so that owners can review access requests without needing read access to the consumer's APIKey or Secret.

APIKeyRequest resources are created and maintained by the controller, not by users directly. When a developer creates an APIKey in their own namespace, the controller creates a matching APIKeyRequest in the referenced APIProduct's namespace. There is a one to one mapping between an APIKey and its APIKeyRequest, and the controller keeps the request spec and status in sync with the APIKey. When the APIKey is deleted or enters the `Failed` state, the controller removes the shadow APIKeyRequest.

The API owner reviews the APIKeyRequest and creates an [APIKeyApproval](apikeyapproval.md) referencing it to approve or deny access.

## APIKeyRequest

| **Field** | **Type**                                      | **Required** | **Description**                               |
|-----------|-----------------------------------------------|:------------:|-----------------------------------------------|
| `spec`    | [APIKeyRequestSpec](#apikeyrequestspec)       | Yes          | The specification for the APIKeyRequest custom resource |
| `status`  | [APIKeyRequestStatus](#apikeyrequeststatus)   | No           | The status for the custom resource            |

## APIKeyRequestSpec

| **Field**       | **Type**                                            | **Required** | **Description**                                                              |
|-----------------|-----------------------------------------------------|:------------:|------------------------------------------------------------------------------|
| `apiProductRef` | [LocalAPIProductReference](#localapiproductreference) | Yes        | Reference to the APIProduct this request belongs to, in the same namespace as the APIKeyRequest |
| `planTier`      | String                                              | Yes          | Tier of the requested plan (e.g., "premium", "basic", "enterprise")          |
| `useCase`       | String                                              | Yes          | Description of how the API key will be used                                  |
| `requestedBy`   | [RequestedBy](#requestedby)                         | Yes          | Information about who requested the API key                                  |
| `apiKeyRef`     | [APIKeyReference](#apikeyreference)                 | Yes          | Reference to the APIKey this request shadows, in the consumer's namespace    |
| `expiresAt`     | Timestamp                                           | No           | Expiration time requested by the consumer                                    |

### LocalAPIProductReference

| **Field** | **Type** | **Required** | **Description**                                              |
|-----------|----------|:------------:|--------------------------------------------------------------|
| `name`    | String   | Yes          | Name of the APIProduct in the same namespace as the APIKeyRequest |

### RequestedBy

| **Field** | **Type** | **Required** | **Description**                                        |
|-----------|----------|:------------:|--------------------------------------------------------|
| `userId`  | String   | Yes          | Identifier of the user requesting the API key          |
| `email`   | String   | Yes          | Email address of the user (must be valid email format) |

### APIKeyReference

| **Field**   | **Type** | **Required** | **Description**                              |
|-------------|----------|:------------:|----------------------------------------------|
| `name`      | String   | Yes          | Name of the APIKey in the consumer's namespace |
| `namespace` | String   | Yes          | Namespace of the referenced APIKey           |

## APIKeyRequestStatus

| **Field**    | **Type**                          | **Description**                                                     |
|--------------|-----------------------------------|---------------------------------------------------------------------|
| `conditions` | [][ConditionSpec](#conditionspec) | Latest observations of the APIKeyRequest's state, synced from the APIKey |

### ConditionSpec

Standard Kubernetes condition type with the following fields:

| **Field**            | **Type**  | **Description**                                                                   |
|----------------------|-----------|-----------------------------------------------------------------------------------|
| `type`               | String    | Condition type. Valid types: `Pending`, `Approved`, `Denied`, `Failed`, `Expired` |
| `status`             | String    | Status of the condition: `True`, `False`, or `Unknown`                            |
| `reason`             | String    | Unique, one-word, CamelCase reason for the condition's last transition            |
| `message`            | String    | Human-readable message indicating details about the transition                    |
| `lastTransitionTime` | Timestamp | Last time the condition transitioned from one status to another                   |
| `observedGeneration` | Integer   | The .metadata.generation that the condition was set based upon                    |

The controller copies these conditions from the shadowed APIKey, so the APIKeyRequest status reflects the same approval state that the consumer sees on their APIKey.

## High level example

The resource below is what the controller creates for an APIKey. It is shown for reference; owners read it to review a request, they do not normally create it by hand.

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyRequest
metadata:
  name: apikeyrequest-sample
  namespace: payment-services
spec:
  apiProductRef:
    name: payment-api
  planTier: premium
  useCase: Building a mobile payment application for retail customers
  requestedBy:
    userId: john-doe-123
    email: john.doe@example.com
  apiKeyRef:
    name: developer-john-premium
    namespace: developer-apps
  expiresAt: "2026-12-31T23:59:59Z"
```

Here the APIKeyRequest lives in the APIProduct's namespace (`payment-services`), while `apiKeyRef` points back to the APIKey in the consumer's namespace (`developer-apps`).

## Namespace placement

The controller places the APIKeyRequest in the namespace of the referenced APIProduct. The target namespace is resolved from the APIKey's `apiProductRef`:

- If `apiProductRef.namespace` is set on the APIKey, that namespace is used.
- If it is empty, the APIKeyRequest is created in the APIKey's own namespace.

This is what keeps the request visible to the API owner while the consumer's APIKey and Secret stay in the consumer's namespace.

## Relationship to APIKey, APIProduct, and APIKeyApproval

### APIKey

The APIKeyRequest is a shadow of an [APIKey](apikey.md). The controller mirrors the APIKey's `planTier`, `useCase`, `requestedBy`, and `expiresAt` into the request spec, sets `apiKeyRef` to point back at the APIKey, and keeps the status conditions in sync. The lifecycle of the APIKeyRequest follows the APIKey: it is created with the APIKey and removed when the APIKey is deleted or marked `Failed`.

### APIProduct

The APIKeyRequest lives in the APIProduct's namespace and references it through `apiProductRef`. Because the reference is local to the request's namespace, only the APIProduct name is needed.

### APIKeyApproval

An [APIKeyApproval](apikeyapproval.md) references the APIKeyRequest by name through its `apiKeyRequestRef` to approve or deny the request. When an approval decision is made, the controller updates the APIKey conditions, and those conditions are then synced back onto the APIKeyRequest status.

## Request Workflow

1. Developer creates a Secret with their API key in their namespace.
2. Developer creates an **APIKey** resource referencing that Secret and an APIProduct.
3. The controller creates a corresponding **APIKeyRequest** shadow resource in the APIProduct's namespace.
4. The approval decision is made based on the APIProduct's `approvalMode`:
   - **Automatic mode**: the APIKey is approved automatically, no APIKeyApproval is needed.
   - **Manual mode**: the API owner reviews the APIKeyRequest and creates an **APIKeyApproval** referencing it.
5. The controller processes the decision, updates the APIKey conditions, and syncs them onto the APIKeyRequest status.
6. When the APIKey is deleted or enters the `Failed` state, the controller deletes the shadow APIKeyRequest.
