# The APIKeyApproval Custom Resource Definition (CRD)

## Overview

The APIKeyApproval CRD is part of the Developer Portal extension for Kuadrant. It represents the approval or denial decision for an APIKeyRequest. When a developer requests API access through an APIKeyRequest, an administrator or automated system can create an APIKeyApproval resource to approve or deny that request. This resource captures the decision, the reviewer's identity, the review timestamp, and optional reasoning for the decision.

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

When an APIKeyApproval is created with `approved: true`, the controller processes the approval and updates the corresponding APIKey resource conditions, setting the `Approved` condition to `True`, which allows the API key to be used for authentication.

When an APIKeyApproval is created with `approved: false`, the controller updates the corresponding APIKey resource conditions, setting the `Denied` condition to `True`, and the API key remains inactive.

### APIKey

APIKey is the primary resource that developers create to request API access. The APIKeyRequest is a shadow resource that represents the approval workflow for that APIKey. The APIKeyApproval indirectly affects the APIKey by approving or denying the associated APIKeyRequest, with the decision reflected through the APIKey's status conditions.

## Approval Workflow

1. Developer creates a Secret with their API key in their namespace
2. Developer creates an **APIKey** resource requesting access to an APIProduct, referencing the secret
3. Controller creates a corresponding **APIKeyRequest** shadow resource in the APIProduct's namespace
4. Approval decision is made based on the APIProduct's `approvalMode`:
   - **Automatic mode**: APIKey is automatically approved (no APIKeyApproval needed)
   - **Manual mode**: An administrator creates an **APIKeyApproval** resource
5. The controller processes the approval decision and updates the APIKey status conditions accordingly
6. If approved (condition `Approved: True`), the API key from the developer's secret is activated for use
7. If denied (condition `Denied: True`), the APIKey is marked as denied and remains inactive
