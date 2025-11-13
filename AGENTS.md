# AGENTS.md

This file provides guidance to AI Code agents (such as claude.ai/code) when working with code in this repository.

## Project Overview

This is a Kubernetes controller that reconciles Developer Portal capabilities based on Kuadrant resources, such as Plan Policies. It's built using the Kubebuilder framework (v4) and operator-sdk v1.41.1.

**Domain**: kuadrant.io
**API Group**: devportal.kuadrant.io
**Primary Resource**: APIProduct (v1alpha1)

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
```

### Bundle Operations (Operator Lifecycle Manager)
```bash
make bundle            # Generate bundle manifests
make bundle-build      # Build bundle image
```

## Architecture

### Project Structure
- **api/v1alpha1/**: Kubernetes API definitions
    - `apiproduct_types.go`: APIProduct CRD schema (Spec, Status, and List types)
    - `groupversion_info.go`: API group registration
    - `zz_generated.deepcopy.go`: Auto-generated DeepCopy methods

- **internal/controller/**: Reconciliation logic
    - `apiproduct_controller.go`: APIProductReconciler with Reconcile loop
    - Controller uses client.Client for K8s API access
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
The operator follows the standard Kubernetes controller pattern:
1. Watch APIProduct resources
2. Reconcile loop called on create/update/delete events
3. Compare desired state (Spec) vs actual state
4. Take actions to converge actual state to desired state
5. Update Status to reflect observed state

### Key Dependencies
- **controller-runtime v0.21.0**: Core controller framework
- **kubebuilder**: Project scaffolding and code generation
- **Ginkgo/Gomega**: Testing framework
- **operator-sdk v1.41.1**: Operator tooling

## Important Notes

### Modifying APIs
1. Edit types in `api/v1alpha1/apiproduct_types.go`
2. Run `make manifests generate` to regenerate code and CRDs
3. The APIProduct CRD currently has a placeholder `Foo` field - this should be replaced with actual fields

### Controller Implementation
The reconciler in `internal/controller/apiproduct_controller.go` is scaffolded but not implemented. The Reconcile function needs business logic added.

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
