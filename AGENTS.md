# AGENTS.md

This file provides guidance to AI Code agents (such as claude.ai/code) when working with code in this repository.

## Project Overview

This is a Kubernetes controller that reconciles Developer Portal capabilities based on Kuadrant resources, such as Plan Policies. It's built using the Kubebuilder framework (v4) and operator-sdk v1.41.1.

**Domain**: kuadrant.io
**API Group**: devportal.kuadrant.io
**Resources (v1alpha1)**: 
- `APIProduct`: Represents an API offering in the developer portal
- `APIKey`: Represents a developer's request for API access (created in consumer namespace)
- `APIKeyRequest`: Shadow resource for RBAC-based request review (created in owner namespace)
- `APIKeyApproval`: API owner's decision to approve/deny access requests

## Design Documents

**RBAC Design**: The project implements namespace-based RBAC for API management. Read the full design at:
https://github.com/Kuadrant/kuadrant-console-plugin/blob/main/docs/designs/2026-03-26-api-management-rbac-design.md

Key concepts from the design:
- **Namespace isolation**: Consumers create APIKeys in their namespace, owners review APIKeyRequests in their namespace
- **Shadow resources**: APIKeyRequest mirrors APIKey in owner's namespace for RBAC-enforced discovery
- **Cross-namespace references**: APIKey references APIProduct across namespaces; APIKeyApproval references APIKey across namespaces
- **Secret projection**: API key values projected to status field, eliminating need for secret read permissions
- **Conditions pattern**: Uses conditions array (Pending/Approved/Denied/Failed) following CertificateSigningRequest pattern

## Development Commands

### Building and Running
```bash
make build              # Build manager binary (output: bin/manager)
make run               # Run controller locally (not in cluster)
make docker-build      # Build docker image (IMG=controller:latest)
```

### Code Generation
After modifying API types in `api/v1alpha1/*_types.go`:
```bash
make manifests         # Generate CRDs, RBAC, webhook configs
make generate          # Generate DeepCopy methods
```

### Testing
```bash
make test              # Run unit tests with coverage
make test-e2e          # Run e2e tests in Kind cluster (creates/deletes cluster automatically)
go test ./internal/controller -v  # Run controller tests only
```

### Linting and Formatting
```bash
make fmt               # Run go fmt
make vet               # Run go vet
make lint              # Run golangci-lint
make lint-fix          # Run golangci-lint with auto-fixes
```

### Deployment
```bash
make install           # Install CRDs to cluster
make deploy            # Deploy controller to cluster
make uninstall         # Remove CRDs from cluster
make undeploy          # Remove controller from cluster
make local-deploy      # Deploy controller from current code
```

### Build Utilities
```bash
make build-installer   # Generate consolidated YAML with CRDs and deployment
make gateway-api-crds  # Download Gateway API CRDs for testing
make setup-test-e2e    # Set up Kind cluster for e2e tests if it doesn't exist
make cleanup-test-e2e  # Tear down the Kind cluster used for e2e tests
```

## Architecture

### Project Structure
- **api/v1alpha1/**: Kubernetes API definitions
    - `apiproduct_types.go`: APIProduct CRD schema (Spec, Status, and List types)
    - `apikey_types.go`: APIKey CRD schema for consumer access requests
    - `apikeyrequest_types.go`: APIKeyRequest CRD schema for owner-side request review
    - `apikeyapproval_types.go`: APIKeyApproval CRD schema for approval decisions
    - `groupversion_info.go`: API group registration
    - `zz_generated.deepcopy.go`: Auto-generated DeepCopy methods

- **internal/controller/**: Reconciliation logic
    - `apiproduct_controller.go`: APIProductReconciler for API product lifecycle
    - `apikey_controller.go`: APIKeyReconciler for consumer API key requests
    - `apikeyrequest_controller.go`: APIKeyRequestReconciler for request processing
    - Controllers use client.Client for K8s API access
    - RBAC permissions defined via kubebuilder markers (`+kubebuilder:rbac`)

- **cmd/main.go**: Operator entry point
    - Sets up controller-runtime Manager
    - Configures metrics server (default secure HTTPS on port 8443)
    - Health/readiness probes on port 8081
    - Leader election support (disabled by default)
    - Certificate watchers for metrics and webhooks
    - HTTP/2 disabled by default for security

- **config/**: Kustomize manifests
    - `config/crd/`: CRD definitions
    - `config/rbac/`: RBAC roles and bindings
    - `config/manager/`: Controller deployment
    - `config/samples/`: Example CR manifests
    - `config/prometheus/`: Prometheus ServiceMonitor

### Controller Pattern
The operator follows the standard Kubernetes controller pattern with multiple reconcilers:

**APIProductReconciler**:
1. Watches APIProduct resources
2. Discovers associated PlanPolicy and AuthPolicy from HTTPRoute
3. Fetches and stores OpenAPI spec
4. Updates status with discovered plans and auth scheme

**APIKeyReconciler**:
1. Watches APIKey resources (consumer namespace)
2. Creates APIKeyRequest shadow resource in owner namespace
3. Processes APIKeyApproval decisions
4. Creates API key secrets and projects values to status
5. Updates conditions (Pending/Approved/Denied)

**APIKeyRequestReconciler**:
1. Watches APIKeyRequest resources (owner namespace)
2. Handles automatic approval mode
3. Syncs status with related APIKey

All controllers:
- Compare desired state (Spec) vs actual state
- Take actions to converge actual state to desired state
- Update Status to reflect observed state

### Key Dependencies
- **controller-runtime v0.21.0**: Core controller framework
- **kubebuilder**: Project scaffolding and code generation
- **Ginkgo/Gomega**: Testing framework
- **operator-sdk v1.41.1**: Operator tooling

## Important Notes

### Modifying APIs
1. Edit types in `api/v1alpha1/*_types.go`
2. Run `make manifests generate` to regenerate code and CRDs
3. Update RBAC role definitions in `config/rbac/` if new permissions are needed
4. Update sample manifests in `config/samples/` to reflect new fields

### RBAC Architecture
The project implements namespace-based RBAC with three personas:
- **API Consumer**: Creates APIKey in their namespace, can read their own APIKey status
- **API Owner**: Views APIKeyRequest in their namespace, creates APIKeyApproval decisions
- **API Admin**: Manages APIProduct resources and overall API catalog

Critical security invariants:
- Consumers CANNOT see other consumers' APIKeys (namespace isolation)
- Owners CANNOT see APIKey secrets (shadow resource pattern)
- APIKeyApproval namespace MUST match APIProduct namespace (validated by controller)
- API key values projected to status field (no secret read permissions required)

### Testing Environment
- E2e tests use Kind cluster named `developer-portal-controller-test-e2e`
- The cluster is automatically created/destroyed by `make test-e2e`
- Unit tests use controller-runtime's envtest framework
- ENVTEST binaries are managed in `bin/` directory

### Deployment Options
- Local development: `make run` (runs outside cluster)
- In-cluster: `make deploy` (requires existing Kubernetes cluster)
- Docker: `make docker-build docker-push deploy IMG=<your-registry>/<image>:<tag>`

### Makefile Variables
- `VERSION`: Project version (default: 0.0.1)
- `IMG`: Controller image (default: controller:latest)
- `CONTAINER_TOOL`: Container build tool (default: docker, can use podman)
- `KIND_CLUSTER`: Kind cluster name for e2e tests
