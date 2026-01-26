# Iron. Implementation Checklist (Closed System Refactor)

## Phase 1 — Kernel Freeze (L0) & Identity (L1)
- [x] **L0: Kernel (Invariants)**
    - [x] `Time.ts` (Keep)
    - [x] `Invariant.ts` (Keep)
    - [x] `Crypto.ts` (Extract Primitives)
    - [x] `Budgets.ts` (New: Energy, Risk)
    - [x] *Remove*: Identity, Evidence, Ledger
- [x] **L1: Identity & Trust**
    - [x] `Identity.ts` (Move from L0)
    - [x] `Delegation.ts` (New: Chain of Trust)
    - [x] Tests: Signature verification, Delegation checking

## Phase 2 — Truth (L2) & Simulation (L3)
- [x] **L2: Truth & State**
    - [x] `Evidence.ts` (Move from L0)
    - [x] `State.ts` (Refactor L1 Truth)
    - [x] `Assertions.ts` (New wrapper)
- [x] **L3: Simulation & Forecast**
    - [x] `Forecast.ts` (Refactor L2 TrendAnalyzer)
    - [x] `Simulation.ts` (Refactor L3 Engine)
    - [x] Tests: Forecast impact, Budget consumption

## Phase 3 — Protocol (L4) & Accountability (L5)
- [x] **L4: Protocol Execution**
    - [x] `Protocol.ts` (Keep DSL)
    - [x] Ensure execution uses L0 Budgets
- [x] **L5: Accountability & Audit**
    - [x] `AuditLog.ts` (Move L0 Ledger here)
    - [x] `Accountability.ts` (Keep SLA/Incentives)
    - [x] Tests: Append-only verification

## Phase 4 — Interfaces (L6) & Chaos
- [x] **L6: Interface Boundary**
    - [x] `Interface.ts` (Update imports)
- [x] **Chaos (Verifier)**
    - [x] Ensure Chaos validates governance but doesn't govern
    - [x] Update imports

## System Cleanup
- [x] Update all imports
- [x] Verify full system tests

## Security Hardening (New)
- [x] **L0 Crypto Hardening**
    - [x] Implement `Ed25519` signing/verification wrappers
    - [x] Enforce SHA-256 everywhere
- [x] **Identity & Intent**
    - [x] Update `Identity` to use Ed25519 Public Keys
    - [x] Create `Intent` object structure (Signed Action)
    - [x] Refactor `State.apply` to accept ONLY Signed Intents
- [x] **Protocol Security**
    - [x] Protocols must be signed and versioned
- [x] **Audit**
    - [x] Verify Hash-chaining uses strict SHA-256(prev + intent)
    - [x] Ensure non-repudiation

## Formal Gap Filling (Addressing Gaps 1-6)
- [x] **Gap 1: Delegation Scope** (`delegate.scope ⊆ delegator.scope`)
- [x] **Gap 2: Protocol Conflict** (Reject if >1 protocol applies)
- [x] **Gap 3: Monotonic Time** (`timestamp >= prev.timestamp`)
- [x] **Gap 4: Revocation** (Transitive & Terminal)
- [x] **Gap 5: Accountability Completeness** (Log *Attempted* Actions)
- [x] **Gap 6: Budget Atomicity** (Exhaustion = Zero State Change)

## Formal Model Alignment (TLA+ / Alloy)
- [x] **Safety Invariants (TLA+)**
    - [x] INV-ID-1: All events signed (Enforced by `State.apply`)
    - [x] INV-ID-2: No hidden actors (Enforced by `Principal` check)
    - [x] INV-ACC-1: Every event logged (`AuditLog.append`)
    - [x] INV-ID-3: Scope, INV-TIME-1 Monotonicity, INV-ACC-2 Attempts
- [x] **Structural Invariants (Alloy)**
    - [x] SignedIntentOnly (`Intent` interface)
    - [x] LogChain (Hash-linked LogEntry)
    - [x] Protocol Conflict Rejection

## Operationalization (Runtime Guards & Atomicity)
- [x] **Runtime Architecture**
    - [x] Create `GovernanceKernel` (Trusted Orchestrator)
    - [x] Implement `Guard` Pattern (`Identity`, `Intent`, `Protocol`, `Time`, `Budget`)
- [x] **Atomic Execution Flow (12-Step)**
    - [x] Log ATTEMPT before execution
    - [x] Enforce Pre-computation of Cost & Budget Reservation
    - [x] Log OUTCOME after execution
- [x] **Traceability & Testing**
    - [x] Map Checks: Invariant -> Guard -> Test
    - [x] Implement Property-Based Fuzzer (Chaos)
    - [x] Verify Failure Semantics (Reject vs Halt)

## Stratum IV: Risk Engine & Console (Final Delivery)
- [x] **Risk & Obligation Engine**
    - [x] `RiskRegistry.ts` (Track Compliance & Risk)
    - [x] Standard Protocols (`ISO27001`, `FinancialControls`)
- [x] **Protocol Studio**
    - [x] JSON DSL Editor
    - [x] Simulation Integration
- [x] **Console UI**
    - [x] Dashboard (Metrics)
    - [x] Risk Heatmap
    - [x] Studio Tab

## Stratum V: Iron Wallet (Personal Continuity)
- [x] **Constitution & Doctrine**
    - [x] Scope Laws (`IRON_WALLET_CONSTITUTION.md`)
    - [x] Trust Doctrine (`IRON_WALLET_DOCTRINE.md`)
- [x] **Protocols (L4)**
    - [x] `SovereignSilence` (Deadman Switch)
    - [x] `MedicalEmergency` (Incapacity Access)
- [x] **Interface (L6)**
    - [x] `IronWalletInterface.ts` (API Gateway)
    - [x] Verification: `System.test.ts` (Lazarus Reset)

## Stratum VI: Iron Habit (Cryptographic Discipline)
- [x] **Constitution**
    - [x] `IRON_HABIT_CONSTITUTION.md` (Commitment Engine)
- [x] **Protocols (L4)**
    - [x] `DailyJournal` (Streak Logic)
    - [x] `RestDay` (Budget Logic)
- [x] **Interface (L6)**
    - [x] `IronHabitInterface.ts` (Check-In & Skip)
    - [x] Verification: `System.test.ts` (Streak & Budget)

## Stratum VII: Iron Team (Cryptographic Coordination)
- [x] **Constitution**
    - [x] `IRON_TEAM_CONSTITUTION.md` (Coordination Engine)
- [x] **Protocols (L4)**
    - [x] `RoleDelegation` (Card Issuance)
    - [x] `TeamSync` (Cadence Sync)
- [x] **Interface (L6)**
    - [x] `IronTeamInterface.ts` (Grant & Sync)
    - [x] Verification: `System.test.ts` (Hierarchy & Heartbeat)

## Stratum VIII: Iron Performance (Verifiable MIS)
- [x] **Constitution**
    - [x] `IRON_PERFORMANCE_CONSTITUTION.md` (Insight Engine)
- [x] **Protocols (L4)**
    - [x] `KPIAggregation` (Roll-up)
    - [x] `DriftDetection` (Variance)
- [x] **Interface (L6)**
    - [x] `IronPerformanceInterface.ts` (Scorecard & Console)
    - [x] Verification: `System.test.ts` (Aggregation & Drift)

## Stratum IX: Iron Intelligence (Verifiable Evolution)
- [x] **Constitution**
    - [x] `IRON_INTELLIGENCE_CONSTITUTION.md` (Evolution Engine)
- [x] **Protocols (L4)**
    - [x] `SimulationVerification` (Strategy)
    - [x] `AdaptiveEvolution` (Self-Opt)
- [x] **Interface (L6)**
    - [x] `IronIntelligenceInterface.ts` (What-If & War Room)
    - [x] Verification: `System.test.ts` (Sim & Evo)
