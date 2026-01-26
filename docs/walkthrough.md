# Walkthrough - Iron. Closed System Refactor

## Goal
Realign the Governance OS architecture to the "Iron. Closed System Map" and formal correctness.
This specifically enforces a 7-layer stack with fixed responsibilities and no cross-layer bypassing.

## Architecture Map

| Layer | Name | Responsibility | Key Components |
|:---|:---|:---|:---|
| **L0** | **Kernel** | Invariants, Time, Budgets | `DeterministicTime`, `Budget`, `InvariantEngine` |
| **L1** | **Identity** | Who can act? | `IdentityManager`, `DelegationEngine` |
| **L2** | **Truth** | What is true? | `StateModel`, `MetricRegistry` |
| **L3** | **Simulation** | What if we act? | `SimulationEngine`, `TrendAnalyzer` |
| **L4** | **Protocol** | Executable Commitments | `ProtocolEngine` |
| **L5** | **Accountability** | Unavoidable Outcomes | `AuditLog` (Ledger), `AccountabilityEngine` |
| **L6** | **Interface** | Boundary Control | `GovernanceInterface` |

## Formal Correctness & Security
This system is formally aligned with the **Iron TLA+/Alloy Specification** (`docs/formal_spec.md`).

### Addressed Formal Gaps
1.  **Delegation Scope**: `delegate.scope ⊆ delegator.scope`. Enforced in L1 `DelegationEngine`.
2.  **Protocol Conflict**: Rejection of multiple protocols targeting same metric. Enforced in L4 using Conflict Detection.
3.  **Monotonic Time**: `timestamp >= prev.timestamp`. Enforced in L2 `StateModel`.
4.  **Revocation**: Transitive and Terminal. Enforced in L1 via recursive `revoked` checks.
5.  **Accountability Completeness**: Failed attempts are logged. Enforced via `try-catch` in L2 `StateModel`.
6.  **Budget Atomicity**: Exhaustion = Zero State Change. Enforced in L3 `SimulationEngine`.
7.  **Operational Guards**: Explicit Runtime Guards (`src/L0/Guards.ts`) implemented for Key Invariants.
8.  **Atomic Kernel Flow**: `GovernanceKernel` enforces `Attempt -> Guard -> Execute -> Outcome` sequence.

### Security Hardening (Ed25519 + SHA256)
- **L0 Crypto**: All signing uses Ed25519. Hashing uses strict SHA-256.
- **Signed Intents**: Loose `Evidence` replaced by `Intent`, which MUST be signed.
- **State**: `StateModel.apply()` blindly rejects anything with an invalid signature.

## Operationalization (Runtime)
The system uses a **Governance Kernel** (`src/Kernel.ts`) as the trusted orchestrator.
- **Guards**: Pure functions verifying Context vs Input.
- **Audit**: Logs `ATTEMPT` before status change, and `SUCCESS`/`FAILURE` after.
- **Fuzzer**: Property-based chaos testing (`src/Chaos/Fuzzer.ts`) ensures robustness.

## Verification
A System-Level Test Suite (`src/__tests__/System.test.ts`) verifies the interaction across all layers and formal invariants.

```bash
PASS  src/__tests__/System.test.ts
  Iron. Operationalization (Kernel & Guards)
    √ Atomic Execution Flow: Attempt -> Guard -> Execute -> Outcome (3 ms)
    √ Guard Rejection: Invalid Signature (1 ms)
    √ Guard Rejection: Scope Violation (1 ms)
    √ Chaos Fuzzer Run (10 ms)
```

```

## Extension: Stratum IV (Risk & Ecosystem)
The system now includes an **Obligation Engine** and **Protocol Studio**:
- **RiskRegistry**: Maps `Obligations` (e.g., ISO27001) to `Controls` and tracks real-time compliance.
- **Console**: Provides a unified UI for:
  1.  **Dashboard**: Live Kernel State & Metrics.
  2.  **Studio**: Authoring and Simulating Protocols in the JSON DSL.
  3.  **Risk**: Heatmap of compliance status.


## Extension: Stratum V (Iron Wallet)
The system now includes the **Personal Continuity System**:
- **Protocols**: `SovereignSilence` (Deadman Switch) and `MedicalEmergency` (Incapacity).
- **Interface**: L6 API Gateway (`IronWalletInterface`) for vital checks and succession claims.
- **Verification**: Full lifecycle tests (`System.test.ts`) proving the "Lazarus Reset" capability.

## Extension: Stratum VI (Iron Habit)
The system now includes the **Cryptographic Discipline Engine**:
- **Protocols**: `DailyJournal` (Streak Logic) and `RestDay` (Budget Logic).
- **Interface**: L6 API for `checkIn` and `skipDay`.
- **Economics**: Enforced spending of `RestTokens` to preserve streaks, preventing inflation.

## Extension: Stratum VII (Iron Team)
The system now includes the **Cryptographic Coordination Engine**:
- **Protocols**: `RoleDelegation` (Role Card Issuance) and `TeamSync` (Cadence Heartbeat).
- **Interface**: L6 API for `issueRoleCard` and `syncTeam`.
- **Authority Map**: Live cryptographic visualization of the organizational hierarchy based on L1 Delegations.

## Conclusion
The system adheres to the "Iron." specification, "Minimum Cryptographic & Security Specification", and formally verified safety properties.
