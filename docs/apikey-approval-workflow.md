# APIKey Approval Workflow - Happy Path Validation

This guide walks through the complete happy path workflow for API key approval, from consumer request to enforcement.

## Prerequisites

- Local environment set up with `make local-setup`

## Validation Steps

### 1. Consumer: Create Namespace

As an API consumer, create a namespace for your application:

```bash
kubectl create namespace consumer-app
```

---

### 2. Consumer: Create API Key Secret

Create a secret containing your API key value:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: gamestore-apikey-secret
  namespace: consumer-app
type: Opaque
stringData:
  api_key: <my-api-key>
EOF
```

---

### 3. Consumer: Create APIKey Request

Create an APIKey resource requesting access to the gamestore-api:

```bash
kubectl apply -f - <<EOF
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKey
metadata:
  name: gamestore-apikey
  namespace: consumer-app
spec:
  apiProductRef:
    name: gamestore-api
    namespace: gamestore
  secretRef:
    name: gamestore-apikey-secret
  planTier: gold
  useCase: "Integration with our mobile gaming platform"
  requestedBy:
    userId: user-12345
    email: developer@consumer-app.com
EOF
```

---

### 4. Consumer: Check APIKey Status (Pending)

Check the APIKey status - it should show a Pending condition:

```bash
kubectl get apikey gamestore-apikey -n consumer-app -o jsonpath='{.status}' | yq e -P
```

**Expected output:**

```yaml
status:
  conditions:
  - type: Pending
    status: "True"
    reason: AwaitingApproval
    message: "API key request is awaiting approval"
    lastTransitionTime: "<timestamp>"
  observedGeneration: 1
```

This indicates the request is awaiting approval from the API owner.

---

### 5. Owner: Check APIKeyRequest Exists

As an API owner, check that the APIKeyRequest shadow resource was created in your namespace:

```bash
kubectl get apikeyrequest -n gamestore
```

**Expected output:**

```
NAME                              AGE
consumer-app-gamestore-apikey     <time>
```

**Inspect the apikey request details:**

```bash
kubectl describe apikeyrequest consumer-app-gamestore-apikey -n gamestore
```

Expected: You should see the use case, requester email, plan tier, and reference to the consumer's APIKey.

---

### 6. Owner: Approve the Request

Create an APIKeyApproval resource to approve the request:

```bash
kubectl apply -f - <<EOF
apiVersion: devportal.kuadrant.io/v1alpha1
kind: APIKeyApproval
metadata:
  name: gamestore-approval-12345
  namespace: gamestore
spec:
  apiKeyRequestRef:
    name: consumer-app-gamestore-apikey
  approved: true
  reviewedBy: api-owner@gamestore.com
  reviewedAt: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  reason: "Approved"
  message: "Valid use case for mobile gaming platform integration"
EOF
```

---

### 7. Owner: Check Approval Status

Inspect the approval to confirm it was processed:

```bash
kubectl describe apikeyapproval gamestore-approval-12345 -n gamestore
```

**Expected:**

- `approved: true`
- Reviewer information visible
- Status condition type `Valid` set to `true`

---

### 8. Consumer: Check APIKey Status (Approved)

Back as the consumer, check that the APIKey has been approved:

```bash
kubectl get apikey gamestore-apikey -n consumer-app -o jsonpath='{.status}' | yq e -P
```

The APIKey should now show an `Approved` condition (replacing the previous `Pending` condition):

**Expected output should include:**

```yaml
status:
  conditions:
  - type: Approved
    status: "True"
    reason: Approved
    message: "API key request approved by api-owner@gamestore.com: Valid use case for mobile gaming platform integration"
    lastTransitionTime: "<timestamp>"
  apiKeyValue: "my-secure-api-key-12345"
  limits:
    daily: 100
  apiHostname: ...
  authScheme:
    # ... authentication configuration
```

---

### 9. Verify Enforcement Secret Created

Check that the controller created the enforcement secret in the Kuadrant namespace:

```bash
# Find the enforcement secret using labels (secret name includes a hash suffix)
kubectl get secrets -n kuadrant-system \
  -l "devportal.kuadrant.io/apikey=gamestore-apikey,devportal.kuadrant.io/apikey-namespace=consumer-app"
```

**Expected:**

- A secret exists with a name like `devportal-consumer-app-gamestore-apikey-{8-char-hash}`

**Inspect the secret:**

```bash
# Get the secret name
SECRET_NAME=$(kubectl get secrets -n kuadrant-system \
  -l "devportal.kuadrant.io/apikey=gamestore-apikey,devportal.kuadrant.io/apikey-namespace=consumer-app" \
  -o jsonpath='{.items[0].metadata.name}')

# View the full secret
kubectl get secret -n kuadrant-system $SECRET_NAME -o yaml

# Decode and verify the API key value
kubectl get secret -n kuadrant-system $SECRET_NAME -o jsonpath='{.data.api_key}' | base64 -d
```

**Expected:**

- Secret has appropriate labels:
  - `devportal.kuadrant.io/apiproduct=gamestore-api`
  - `devportal.kuadrant.io/apiproduct-namespace=gamestore`
  - `devportal.kuadrant.io/apikey=gamestore-apikey`
  - `devportal.kuadrant.io/apikey-namespace=consumer-app`
  - `authorino.kuadrant.io/managed-by=authorino`
  - Plus any selector labels from AuthenticationSpec (e.g., `app: gamestore`, `role: admin` for VIP users)
- Secret contains the `api_key` field with correct value (base64 encoded)

---

## Denial Workflow (Owner Changes Mind)

### 10. Owner: Deny the Previously Approved Request

The owner changes their mind and denies the approval by patching the existing APIKeyApproval:

```bash
# Patch the existing approval to denied
kubectl patch apikeyapproval gamestore-approval-12345 -n gamestore --type=merge --patch='{"spec":{"approved":false,"reason":"Denied","message":"Use case no longer meets security requirements"}}'
```

**Verify:**

```bash
kubectl get apikeyapproval gamestore-approval-12345 -n gamestore -o jsonpath='{.spec.approved}'
```

Expected output: `false`

---

### 11. Consumer: Check APIKey Status (Denied)

Back as the consumer, verify the APIKey status has changed to Denied:

```bash
kubectl get apikey gamestore-apikey -n consumer-app -o jsonpath='{.status}' | yq e -P
```

**Expected output should include:**

```yaml
status:
  conditions:
  - type: Denied
    status: "True"
    reason: Denied
    message: "API key request denied by api-owner@gamestore.com: Denied"
    lastTransitionTime: "<timestamp>"
```

**Quick check:**

```bash
kubectl get apikey gamestore-apikey -n consumer-app -o jsonpath='{.status.conditions[?(@.type=="Denied")].status}'
```

Expected output: `True`

**Verify Approved condition is removed:**

```bash
kubectl get apikey gamestore-apikey -n consumer-app -o jsonpath='{.status.conditions[?(@.type=="Approved")]}'
```

Expected: Empty (no Approved condition)

---

### 12. Verify Enforcement Secret is Removed

Check that the controller has removed the enforcement secret, making the API key no longer effective:

```bash
# Try to find the secret using labels
kubectl get secrets -n kuadrant-system \
  -l "devportal.kuadrant.io/apikey=gamestore-apikey,devportal.kuadrant.io/apikey-namespace=consumer-app"
```

**Expected output:**

```
No resources found in kuadrant-system namespace.
```

**Alternative check - list all devportal enforcement secrets:**

```bash
kubectl get secrets -n kuadrant-system -l "devportal.kuadrant.io/apikey"
```

Expected: No resources found (or the specific secret for gamestore-apikey is gone)

---

## Summary

✅ **Complete Workflow Validated!**

### Approval Path

1. ✅ Consumer created namespace
2. ✅ Consumer created APIKey secret  
3. ✅ Consumer created APIKey request (status: Pending)
4. ✅ Owner saw APIKeyRequest in their namespace
5. ✅ Owner approved the request via APIKeyApproval
6. ✅ Consumer's APIKey status updated to Approved
7. ✅ Enforcement secret created for API authentication

### Denial Path

1. ✅ Owner changed mind and patched approval to denied
2. ✅ Consumer's APIKey status updated to Denied
3. ✅ Enforcement secret removed (API key no longer effective)

This demonstrates the complete lifecycle: **Pending → Approved → Denied**, showing that API access can be revoked by the owner at any time.

---

## Cleanup

```bash
make kind-delete-cluster
```
