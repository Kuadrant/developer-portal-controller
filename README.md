# Developer Portal Controller

Developer Portal APIs and Controllers for Kubernetes-based API management.

## Overview

The Developer Portal Controller provides Kubernetes Custom Resource Definitions (CRDs) for managing API products and API keys in a developer portal ecosystem. It integrates with Kuadrant and Gateway API to provide a complete API lifecycle management solution.

## Custom Resources

### APIProduct

The `APIProduct` resource represents an API offering in the developer portal. It references an HTTPRoute and can include documentation, contact information, and usage plans.

#### Example

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIProduct
metadata:
  name: toystore-api
  namespace: default
spec:
  displayName: "Toystore API"
  description: "A comprehensive API for managing toy inventory, orders, and customer data"
  version: "v1"
  approvalMode: manual
  publishStatus: Published
  tags:
    - retail
    - inventory
    - e-commerce
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: toystore-route
  documentation:
    openAPISpecURL: "https://api.example.com/toystore/openapi.yaml"
    swaggerUI: "https://api.example.com/toystore/docs"
    docsURL: "https://docs.example.com/toystore"
    gitRepository: "https://github.com/example/toystore-api"
    techdocsRef: "url:https://github.com/example/toystore-api"
  contact:
    team: "Platform Team"
    email: "platform@example.com"
    slack: "#api-support"
    url: "https://example.com/support"
status:
  conditions:
  - lastTransitionTime: "2026-01-14T17:02:07Z"
    message: Discovered PlanPolicy toystore-plans targeting HTTPRoute toystore
    reason: Found
    status: "True"
    type: PlanPolicyDiscovered
  - lastTransitionTime: "2026-01-14T17:02:08Z"
    message: Discovered AuthPolicy toystore targeting HTTPRoute toystore
    reason: Found
    status: "True"
    type: AuthPolicyDiscovered
  - lastTransitionTime: "2026-01-14T17:02:07Z"
    message: HTTPRoute toystore/toystore accepted
    reason: HTTPRouteAccepted
    status: "True"
    type: Ready
  discoveredAuthScheme:
    authentication:
      api-key-users:
        apiKey:
          allNamespaces: true
          selector:
            matchLabels:
              app: toystore
        credentials:
          authorizationHeader:
            prefix: APIKEY
        metrics: false
        priority: 0
  discoveredPlans:
  - limits:
      daily: 100
    tier: gold
  - limits:
      daily: 50
    tier: silver
  - limits:
      daily: 10
    tier: bronze
  observedGeneration: 1
  openapi:
    lastSyncTime: "2026-01-14T17:02:07Z"
    raw: |
      ---
      openapi: "3.0.2"
      info:
        title: "Pet Store API"
        version: "1.0.0"
      servers:
        - url: https://toplevel.example.io/v1
      paths:
        /cat:
          get:
            operationId: "getCat"
            responses:
              405:
                description: "invalid input"
          post:
            operationId: "postCat"
            responses:
              405:
                description: "invalid input"
        /dog:
          get:
            operationId: "getDog"
            responses:
              405:
                description: "invalid input"
```

#### APIProduct Spec Fields

- `displayName` (required): Human-readable name for the API product
- `description`: Detailed description of the API product
- `version`: API version (e.g., v1, v2)
- `approvalMode`: Whether access requests are auto-approved (`automatic`) or require manual review (`manual`)
- `publishStatus`: Controls visibility in the catalog (`Draft` or `Published`)
- `tags`: List of tags for categorization and search
- `targetRef`: Reference to the HTTPRoute that this API product represents
- `documentation`: API documentation links (OpenAPI spec, Swagger UI, docs URL, git repository, techdocs)
- `contact`: Contact information for API owners (team, email, Slack, URL)

#### APIProduct Status Fields

- `observedGeneration`: Generation of the most recently observed spec
- `discoveredPlans`: List of plan policies discovered from the HTTPRoute
- `openapi`: OpenAPI specification fetched from the API with sync timestamp
- `conditions`: Current state conditions (Ready, PlanPolicyDiscovered)

---

### APIKey

The `APIKey` resource represents a developer's request for API access. It includes information about the requester, the desired plan tier, and the use case.

#### Example

```yaml
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKey
metadata:
  name: toystore-apikey
  namespace: default
  labels:
    app.kubernetes.io/name: developer-portal-controller
    app.kubernetes.io/managed-by: kustomize
spec:
  apiProductRef:
    name: toystore-api
  planTier: gold
  useCase: "Authentication key for our Toystore API integration"
  requestedBy:
    userId: user-12345
    email: developer@example.com
status:
  phase: Approved
  apiHostname: api.example.com
  reviewedBy: admin@example.com
  reviewedAt: "2025-12-09T10:30:00Z"
  limits:
    daily: 1000
  secretRef:
    name: toystore-apikey-secret
    key: api-key
  canReadSecret: true
  conditions:
    - type: Ready
      status: "True"
      reason: APIKeyReady
      message: APIKey has been approved and secret created
      lastTransitionTime: "2025-12-09T10:30:00Z"
```

#### APIKey Spec Fields

- `apiProductRef` (required): Reference to the APIProduct this APIKey belongs to
- `planTier` (required): Tier of the plan (e.g., "gold", "silver", "bronze", "premium", "basic")
- `useCase` (required): Description of how the API key will be used
- `requestedBy` (required): Information about the requester
  - `userId`: Identifier of the user requesting the API key
  - `email`: Email address of the user (validated with regex pattern)

#### APIKey Status Fields

- `phase`: Current phase of the APIKey (`Pending`, `Approved`, or `Rejected`)
- `apiHostname`: Hostname from the HTTPRoute
- `reviewedBy`: Who approved or rejected the request
- `reviewedAt`: Timestamp when the request was reviewed
- `limits`: Rate limits for the plan
- `secretRef`: Reference to the created Secret containing the API key
  - `name`: Name of the secret
  - `key`: Key within the secret
- `canReadSecret`: Permission to read the APIKey's secret (default: true)
- `conditions`: Latest observations of the APIKey's state

## Development environment setup

Dev env

```bash
make kind-create-cluster
make install
make gateway-api-install
make kuadrant-core-install
```

Deploy controller

```bash
make local-deploy
```

## Usage

### Creating an APIProduct

1. Create an HTTPRoute for your API
2. Create a PlanPolicy to define rate limits and tiers
3. Create an APIProduct referencing the HTTPRoute

### Requesting an APIKey

1. Create an APIKey resource referencing the APIProduct
2. If `approvalMode` is `manual`, wait for approval
3. Once approved, the secret will be created with the API key
4. Use the key from the secret to authenticate API requests

## kubectl Commands

```bash
# List APIProducts
kubectl get apiproducts

# List APIKeys (shortname: apik)
kubectl get apik

# View APIKey details with phase and plan
kubectl get apik -o wide

# Describe an APIKey to see status details
kubectl describe apikey toystore-apikey
```

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
