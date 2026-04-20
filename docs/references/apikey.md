# The APIKey Custom Resource Definition (CRD)

## Overview

The APIKey CRD is part of the Developer Portal extension for Kuadrant. It represents a request for API access credentials by a developer for a specific APIProduct and plan tier. The developer creates a Kubernetes Secret containing their API key in their own namespace, then creates an APIKey resource referencing that secret. When approved, the controller validates and registers the API key for use with the specified APIProduct. The APIKey resource manages the entire lifecycle of API access requests, from initial submission through approval/rejection to credential activation.

## APIKey

| **Field** | **Type**                          | **Required** | **Description**                           |
|-----------|-----------------------------------|:------------:|-------------------------------------------|
| `spec`    | [APIKeySpec](#apikeyspec)         | Yes          | The specification for APIKey custom resource |
| `status`  | [APIKeyStatus](#apikeystatus)     | No           | The status for the custom resource        |

## APIKeySpec

| **Field**       | **Type**                                  | **Required** | **Description**                                                          |
|-----------------|-------------------------------------------|:------------:|--------------------------------------------------------------------------|
| `apiProductRef` | [APIProductReference](#apiproductreference) | Yes       | Reference to the APIProduct this API key provides access to             |
| `secretRef`     | [LocalObjectReference](#localobjectreference) | Yes      | Reference to the secret containing the API key in the consumer's namespace |
| `planTier`      | String                                    | Yes          | Tier of the plan (e.g., "premium", "basic", "enterprise")                |
| `useCase`       | String                                    | Yes          | Description of how the API key will be used                              |
| `requestedBy`   | [RequestedBy](#requestedby)               | Yes          | Information about who requested the API key                              |

### APIProductReference

| **Field**   | **Type** | **Required** | **Description**                              |
|-------------|----------|:------------:|----------------------------------------------|
| `name`      | String   | Yes          | Name of the APIProduct                       |
| `namespace` | String   | Yes          | Namespace of the APIProduct                  |

### LocalObjectReference

| **Field** | **Type** | **Required** | **Description**                                                      |
|-----------|----------|:------------:|----------------------------------------------------------------------|
| `name`    | String   | Yes          | Name of the secret in the same namespace containing the API key (must have an "api_key" entry) |

### RequestedBy

| **Field** | **Type** | **Required** | **Description**                                                |
|-----------|----------|:------------:|----------------------------------------------------------------|
| `userId`  | String   | Yes          | Identifier of the user requesting the API key                  |
| `email`   | String   | Yes          | Email address of the user (must be valid email format)         |

## APIKeyStatus

| **Field**       | **Type**                          | **Description**                                                                   |
|-----------------|-----------------------------------|-----------------------------------------------------------------------------------|
| `apiHostname`   | String                            | Hostname from the HTTPRoute that the APIProduct references                        |
| `limits`        | [Limits](#limits)                 | Rate limits for the plan                                                          |
| `authScheme`    | [AuthScheme](#authscheme)         | Authentication scheme discovered from the APIProduct's AuthPolicy                 |
| `conditions`    | [][ConditionSpec](#conditionspec) | Represents the observations of the APIKey's current state                         |

### ConditionSpec

Standard Kubernetes condition type with the following fields:

| **Field**            | **Type**  | **Description**                                                                   |
|----------------------|-----------|-----------------------------------------------------------------------------------|
| `type`               | String    | Condition type. Valid types: `Approved`, `Denied`, `Failed`                       |
| `status`             | String    | Status of the condition: `True`, `False`, or `Unknown`                            |
| `reason`             | String    | Unique, one-word, CamelCase reason for the condition's last transition            |
| `message`            | String    | Human-readable message indicating details about the transition                    |
| `lastTransitionTime` | Timestamp | Last time the condition transitioned from one status to another                   |
| `observedGeneration` | Integer   | The .metadata.generation that the condition was set based upon                    |

### AuthScheme

| **Field**            | **Type**               | **Description**                                                          |
|----------------------|------------------------|--------------------------------------------------------------------------|
| `authenticationSpec` | AuthenticationSpec     | API key authentication specification from the AuthPolicy                 |
| `credentials`        | Credentials            | Credentials configuration (where to extract the API key from requests)   |

### Limits

| **Field**  | **Type**      | **Required** | **Description**                                                    |
|------------|---------------|:------------:|--------------------------------------------------------------------|
| `daily`    | Integer       | No           | Daily limit of requests for this plan                              |
| `weekly`   | Integer       | No           | Weekly limit of requests for this plan                             |
| `monthly`  | Integer       | No           | Monthly limit of requests for this plan                            |
| `yearly`   | Integer       | No           | Yearly limit of requests for this plan                             |
| `custom`   | [][Rate](#rate) | No         | Additional limits defined in terms of a RateLimitPolicy Rate       |

### Rate

| **Field**  | **Type** | **Required** | **Description**                                                    |
|------------|----------|:------------:|--------------------------------------------------------------------|
| `limit`    | Integer  | Yes          | Maximum value allowed for a given period of time                   |
| `window`   | String   | Yes          | Time period for which the limit applies (pattern: `^([0-9]{1,5}(h\|m\|s\|ms)){1,4}$`) |

## High level example

First, the developer creates a secret in their namespace with the API key:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-payment-api-key
  namespace: developer-apps
type: Opaque
stringData:
  api_key: "<api-key>"
```

Then, the developer creates an APIKey resource:

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKey
metadata:
  name: developer-john-premium
  namespace: developer-apps
spec:
  apiProductRef:
    name: payment-api
    namespace: payment-services
  secretRef:
    name: my-payment-api-key
  planTier: premium
  useCase: Building a mobile payment application for retail customers
  requestedBy:
    userId: john-doe-123
    email: john.doe@example.com
```

## Relationship to APIProduct, AuthPolicy, and APIKeyRequest

### APIProduct

APIKey **must** reference an existing APIProduct via `apiProductRef`. The APIProduct defines the API being accessed and contains approval workflow configuration.

### AuthPolicy

AuthPolicy is applied to the HTTPRoute that the APIProduct references. The APIKey controller discovers the authentication scheme from the AuthPolicy and populates it in the `status.authScheme` field. The AuthPolicy validates incoming API requests by checking the API key from the consumer's secret against configured selectors.

### PlanPolicy

PlanPolicy defines the available tiers and their corresponding rate limits. When an APIKey specifies a `planTier`, the controller validates that this tier exists in the PlanPolicy attached to the HTTPRoute. The discovered rate limits are populated in the `status.limits` field.

### APIKeyRequest

When an APIKey is created, the controller creates a shadow APIKeyRequest resource that represents the approval workflow. The APIKeyRequest is used to track the approval status and connect to APIKeyApproval resources when manual approval is required. Once approved, the controller updates the APIKey conditions to indicate approval status.
