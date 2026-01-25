# The IRON Kernel Specification v1.0

## 1. Core Definitions

### 1.1 The Atom (Action)
An `Action` defines a desired change to the State.
*   **Structure**: `{ ID, Initiator, Payload, Signature, Timestamp }`
*   **Property**: An Action is immutable once signed.

### 1.2 The Transition (Commit)
A `Commit` is the atomic application of an Accepted Action.
*   **Structure**: `{ AttemptID, OldStateHash, NewStateHash, Cost }`
*   **Property**: A Commit establishes a cryptographic link in the `AuditLog`.

## 2. Constitutional Invariants

The Kernel enforces three invariants that cannot be violated, regardless of Protocol logic.

### Invariant I: The Authority Conservation Law
*   *Definition*: No state mutation is valid unless authorized by a chain of signatures originating from a Root Authority.
*   *Enforcement*: `SignatureGuard` (Identity) + `AuthorityGuard` (AuthorityEngine).

### Invariant II: The Budget Conservation Law
*   *Definition*: Every action has a cost. No action can proceed if the actor's budget is insufficient.
*   *Enforcement*: `BudgetGuard`.

### Invariant III: The Invariance of History
*   *Definition*: The `AuditLog` is an append-only Merkle Structure. The `StateHash` is derived from the `AuditLog`.
*   *Enforcement*: `Kernel.commitAttempt` (Hashing Logic).

## 3. The Runtime Lifecycle

1.  **Submit**: Entity signs Action.
2.  **Guard**: Kernel verifies Invariant I (Authority).
3.  **Simulation (Optional)**: L3 Engine (Monte Carlo) forecasts impact.
4.  **Hold**: Action enters `PENDING` state.
5.  **Commit**: 
    *   Kernel verifies Invariant II (Budget).
    *   Protocols (L4) execute deterministic logic.
    *   State is updated.
    *   Invariant III (History) is updated.

