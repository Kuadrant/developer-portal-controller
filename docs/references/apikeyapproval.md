# The APIKeyApproval Custom Resource Definition (CRD)

## Overview

The APIKeyApproval CRD is part of the Developer Portal extension for Kuadrant. It represents the approval or denial decision for an APIKeyRequest. When a developer requests API access through an APIKeyRequest, an administrator or automated system can create an APIKeyApproval resource to approve or reject that request. This resource captures the decision, the reviewer's identity, the review timestamp, and optional reasoning for the decision.

## APIKeyApproval

| **Field** | **Type**                                        | **Required** | **Description**                                    |
|-----------|-------------------------------------------------|:------------:|----------------------------------------------------|
| `spec`    | [APIKeyApprovalSpec](#apikeyapprovalspec)       | Yes          | The specification for APIKeyApproval custom resource |
| `status`  | [APIKeyApprovalStatus](#apikeyapprovalstatus)   | No           | The status for the custom resource                 |

## APIKeyApprovalSpec

| **Field**          | **Type**                                              | **Required** | **Description**                                                          |
|--------------------|-------------------------------------------------------|:------------:|--------------------------------------------------------------------------|
| `apiKeyRequestRef` | [APIKeyRequestReference](#apikeyrequestreference)     | Yes          | Reference to the APIKeyRequest being approved or denied                  |
| `approved`         | Boolean                                               | Yes          | Whether the API key request is approved (`true`) or denied (`false`)     |
| `reviewedBy`       | String                                                | Yes          | Identifier of the person or system who reviewed the request              |
| `reviewedAt`       | Timestamp                                             | Yes          | Timestamp when the request was reviewed                                  |
| `reason`           | String                                                | No           | Reason for the approval or denial decision                               |
| `message`          | String                                                | No           | Additional context about the approval or denial                          |

### APIKeyRequestReference

| **Field** | **Type** | **Required** | **Description**                                   |
|-----------|----------|:------------:|---------------------------------------------------|
| `name`    | String   | Yes          | Name of the APIKeyRequest in the same namespace   |

## APIKeyApprovalStatus

| **Field** | **Type** | **Description**                                                   |
|-----------|----------|-------------------------------------------------------------------|
| -         | -        | Currently no status fields defined                                |

## High level example

### Approving an API Key Request

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyApproval
metadata:
  name: approve-john-premium-request
  namespace: payment-services
spec:
  apiKeyRequestRef:
    name: john-premium-request
  approved: true
  reviewedBy: admin@example.com
  reviewedAt: "2026-04-20T10:30:00Z"
  reason: ValidUseCase
  message: Approved for mobile payment application development
```

### Denying an API Key Request

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyApproval
metadata:
  name: deny-suspicious-request
  namespace: payment-services
spec:
  apiKeyRequestRef:
    name: suspicious-request-123
  approved: false
  reviewedBy: security-team@example.com
  reviewedAt: "2026-04-20T11:15:00Z"
  reason: InsufficientInformation
  message: Use case description does not provide sufficient detail about intended usage
```

## Relationship to APIKeyRequest and APIKey

### APIKeyRequest

APIKeyApproval **must** reference an existing APIKeyRequest via `apiKeyRequestRef`. The APIKeyRequest represents a developer's request for API access and contains information about the requested APIProduct, plan tier, use case, and requester details.

When an APIKeyApproval is created with `approved: true`, the controller processes the approval and updates the corresponding APIKey resource to transition it from `Pending` to `Approved` phase, triggering the creation of the API key secret.

When an APIKeyApproval is created with `approved: false`, the controller updates the corresponding APIKey resource to transition it to `Rejected` phase, and no secret is created.

### APIKey

The APIKeyRequest references an APIKey resource, which is the shadow resource that manages the lifecycle of API access credentials. The APIKeyApproval indirectly affects the APIKey by approving or denying the request that the APIKey is based on.

## Approval Workflow

1. Developer creates an **APIKey** resource requesting access to an APIProduct
2. Controller creates a corresponding **APIKeyRequest** shadow resource
3. If the APIProduct has `approvalMode: manual`, an administrator creates an **APIKeyApproval** resource
4. The controller processes the approval decision and updates the APIKey status accordingly
5. If approved, a Kubernetes Secret containing the API key is created
6. If denied, the APIKey remains in `Rejected` phase without a secret
