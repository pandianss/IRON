# IRON KERNEL BOUNDARY CHARTER

Version 1.0 (Foundational Charter)
Status: Constitutional
Scope: Non-negotiable

## Article I — Purpose of the Kernel

The IRON Kernel exists solely to provide a deterministic governance runtime.

Its exclusive purpose is to:

enforce, validate, and record institutional state transitions arising from authorized actors executing governed protocols under declared authority, obligations, and constraints.

The kernel is not a product, platform, workflow system, business engine, or analytics system.

It is a governance substrate.

## Article II — What the Kernel Is

The kernel is the minimum irreducible system required to:

1. Represent institutional reality as governed state.
2. Resolve identity, authority, and mandate.
3. Validate whether an attempted action is permitted.
4. Execute protocols as state machines.
5. Enforce invariants and sanctions.
6. Produce non-repudiable institutional truth.

Nothing else belongs in the kernel.

## Article III — Kernel Responsibilities (Positive Scope)

The kernel SHALL contain only the following domains:

### 1. Identity & Entity Resolution
- Actors (human, institutional, autonomous)
- Roles and offices
- Assets and governed objects
- Cryptographic identity and signing
- Delegation and revocation
- **Kernel outputs**: “Who is this?”, “In what capacity are they acting?”

### 2. Authority Graph & Mandate Engine
- Authority relationships
- Jurisdiction boundaries
- Powers, duties, prohibitions
- Conditional mandates
- Temporary and emergency powers
- **Kernel outputs**: “Is this actor empowered to attempt this act?”, “Under what authority is this action being invoked?”

### 3. Governed State Model
- Canonical state representations
- Immutable state transition records
- Versioned institutional memory
- Truth resolution mechanisms
- Historical reconstruction capability
- **Kernel outputs**: “What is the official state of reality?”, “How did it reach this state?”

### 4. Protocol Execution Engine
- Protocol definitions as state machines
- Trigger resolution
- Precondition validation
- Action authorization
- Consequence dispatch
- **Kernel outputs**: “Which protocol applies?”, “Is the protocol execution valid?”, “What transitions must occur?”

### 5. Invariant & Law Enforcement Engine
- Hard invariants (never violated)
- Soft invariants (violation-recording)
- Constraint evaluation
- Sanction triggers
- Emergency override handling
- **Kernel outputs**: “Does this violate institutional law?”, “What enforcement must occur?”

### 6. Institutional Ledger & Evidence System
- Non-repudiable action logs
- Authority trails
- Protocol traces
- Violation and override records
- Cryptographically verifiable history
- **Kernel outputs**: “What is provably true?”, “Who caused what, when, and under which mandate?”

## Article IV — What the Kernel Is Not (Negative Scope)

The kernel SHALL NOT contain:
- Business workflows
- Domain rules (banking, HR, compliance, education, etc.)
- UI logic or presentation models
- Analytics, KPIs, or dashboards
- Optimization logic
- Notification systems
- Scheduling engines
- Recommendation engines
- AI/ML models
- Data visualization
- Product-specific policies
- Organizational heuristics

The kernel does not “help,” “suggest,” “optimize,” “coach,” or “manage.”
It permits, forbids, records, and enforces.

## Article V — Kernel Interfaces

The kernel exposes only constitutional interfaces:
- **Identity Interface**: Resolve actor, Assert capacity, Validate delegation
- **Authority Interface**: Verify mandate, Test jurisdiction, Evaluate prohibitions
- **Protocol Interface**: Register protocol, Invoke protocol, Query protocol state
- **Law Interface**: Register invariants, Evaluate compliance, Trigger enforcement
- **State Interface**: Read governed state, Propose transition, Commit validated transition
- **Evidence Interface**: Retrieve trace, Generate proof, Reconstruct history

No interface may expose business abstractions, product assumptions, or user experience concerns.

## Article VI — Kernel Design Principles

The kernel SHALL be:
- **Minimal** – fewer primitives, not more features
- **Deterministic** – same input, same institutional outcome
- **Composable** – all higher behavior emerges from protocols
- **Hostile-environment safe** – assumes malicious actors
- **Audit-first** – truth generation precedes convenience
- **Product-agnostic** – no vertical knowledge
- **Politically neutral** – enforces declared law only

## Article VII — Product Separation Doctrine

All products (IRON Control, IRON Command, IRON Audit, IRON Discipline, etc.) exist entirely outside the kernel.
They may:
- define protocols
- register laws
- interpret state
- visualize consequences
- guide users

They may not:
- bypass authority resolution
- directly mutate governed state
- suppress evidence
- override invariants
- embed enforcement logic

All power flows only through the kernel.

## Article VIII — Change Control Law

Any proposed kernel change must:
1. Identify which core responsibility it strengthens.
2. Demonstrate impossibility at the product layer.
3. Prove minimality.
4. Preserve backward constitutional compatibility.
5. Be justified as governance infrastructure, not convenience.

Any feature whose removal does not collapse governance capability SHALL be removed.

## Article IX — Kernel Completion Criterion

The kernel SHALL be considered foundationally complete when:
- no new core primitives are being added
- all new capabilities emerge via protocols
- all products compile into existing kernel operations
- the kernel can remain frozen while products evolve

## Article X — Foundational Statement

The IRON Kernel is not built to serve products.
Products are built to prove the kernel.
The kernel exists to make authority executable, obligation enforceable, and truth institutional.

---

# IRON KERNEL PRIMITIVE SET

Version 1.0 — Foundational
Status: Constitutional / Non-Negotiable

## Part I — Foundational Ontology

### 1. Entity
An Entity is any identifiable subject or object that can participate in governance.
- **Attributes**: EntityID, EntityType (Actor|Office|Asset|System|Abstract), IdentityProof, Status.

### 2. Identity
Identity is the binding between an Entity and its verifiable existence.
- **Properties**: PublicKey, VerificationMethod, ValidityWindow, DelegationChain.

### 3. Capacity
A Capacity is the role or office in which an Entity is acting.
- **Properties**: CapacityID, HeldBy EntityID, ConferredBy AuthorityID, Scope, Validity, RevocationConditions.

### 4. Authority
Authority is a primitive relation defining power, jurisdiction, and mandate.
- **Properties**: AuthorityID, Source, Grants Capacities, Permits Actions, Imposes Obligations, BoundedBy Jurisdiction.

### 5. Jurisdiction
Jurisdiction defines the boundary within which authority is valid (entities, assets, time, space).
- **Properties**: JurisdictionID, ScopeDefinition, InclusionRules, ExclusionRules, TemporalBoundaries.

### 6. Governed State
Canonical institutional memory.
- **Properties**: StateID, StateSchema, CurrentValue, Version, DerivationHistory.

### 7. Protocol
Formal state machine defining valid institutional transitions.
- **Properties**: ProtocolID, TriggerConditions, Preconditions, AuthorizedCapacities, StateTransitions, CompletionConditions.

### 8. Action
A signed attempt to invoke a protocol.
- **Properties**: ActionID, Initiator EntityID, InvokedCapacity, ProtocolReference, DeclaredIntent, Timestamp, Signature.

### 9. Invariant
A non-negotiable law over governed state.
- **Properties**: InvariantID, Predicate, Scope, Severity, EnforcementDirective.

### 10. Sanction
A mandatory consequence produced by the kernel.
- **Properties**: SanctionID, Trigger, Target, Effect, ExecutionMode.

### 11. Override
A formally authorized law breach.
- **Properties**: OverrideID, AuthorizingAuthority, Scope, JustificationRecord, AuditObligation.

### 12. Evidence
The institutional truth substrate.
- **Properties**: EvidenceID, LinkedAction, AuthorityTrace, ProtocolTrace, StateDiff, ImmutabilityProof.

## Part II — Primitive Relations
- Entity holds Capacity
- Authority confers Capacity
- Capacity permits Action
- Action invokes Protocol
- Protocol transitions Governed State
- Invariant constrains State
- Violation triggers Sanction
- Override authorizes Violation
- Evidence attests everything

## Part III — Kernel Services
1. Identity Resolution Service
2. Authority & Jurisdiction Engine
3. Protocol Execution Engine
4. State Transition Engine
5. Law & Invariant Engine
6. Sanction Dispatcher
7. Evidence & Ledger Engine
8. Kernel Integrity Service
