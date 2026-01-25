import type { Action, ActionPayload } from './L2/State.js';
import { StateModel, MetricRegistry } from './L2/State.js';
import { IdentityManager, AuthorityEngine } from './L1/Identity.js';
import { ProtocolEngine } from './L4/Protocol.js';
import type { Mutation } from './L4/Protocol.js';
import { AuditLog } from './L5/Audit.js';
import { SignatureGuard, ScopeGuard, TimeGuard, BudgetGuard } from './L0/Guards.js';
import { Budget, LogicalTimestamp } from './L0/Kernel.js';
import type { KernelState, EntityID, ActionID, CapacityID, JurisdictionID } from './L0/Ontology.js';

export type AttemptID = string;
export type AttemptStatus = 'PENDING' | 'ACCEPTED' | 'REJECTED' | 'COMMITTED' | 'ABORTED';

/**
 * 8. Action (Primitive)
 * A signed attempt to invoke a protocol.
 */
export interface Attempt {
    id: AttemptID;
    initiator: EntityID;
    protocolId: string;
    action: Action;
    cost: number;
    timestamp: LogicalTimestamp;
    status: AttemptStatus;
}

export interface Commit {
    attemptId: AttemptID;
    oldStateHash: string; // From Evidence Trace
    newStateHash: string; // From Evidence Trace
    cost: number;
    timestamp: string;
    status: 'COMMITTED';
}

export class GovernanceKernel {
    private attempts: Map<AttemptID, Attempt> = new Map();
    private lifecycle: KernelState = 'UNINITIALIZED';

    constructor(
        private identity: IdentityManager,
        private authority: AuthorityEngine,
        private state: StateModel,
        private protocols: ProtocolEngine,
        private audit: AuditLog,
        private registry: MetricRegistry
    ) {
        this.transition('CONSTITUTED');
    }

    public get Lifecycle() { return this.lifecycle; }

    /**
     * II.2 State Transition Law (Charter Principle)
     */
    private transition(to: KernelState) {
        const from = this.lifecycle;

        // Illegal Transitions
        if (from === 'VIOLATED' && to === 'ACTIVE') throw new Error("Kernel Error: Cannot transition VIOLATED -> ACTIVE directly. Must RECOVER.");
        if (from === 'DISSOLVED') throw new Error("Kernel Error: Kernel is DISSOLVED. No further transitions allowed.");

        const allowed = {
            'UNINITIALIZED': ['CONSTITUTED'],
            'CONSTITUTED': ['ACTIVE'],
            'ACTIVE': ['SUSPENDED', 'VIOLATED', 'DISSOLVED'],
            'SUSPENDED': ['ACTIVE', 'DISSOLVED'],
            'VIOLATED': ['RECOVERED', 'DISSOLVED'],
            'RECOVERED': ['ACTIVE', 'SUSPENDED'],
            'DISSOLVED': []
        } as Record<KernelState, KernelState[]>;

        if (from !== 'UNINITIALIZED' && !allowed[from].includes(to)) {
            throw new Error(`Kernel Violation: Illegal State Transition ${from} -> ${to}`);
        }

        this.lifecycle = to;
    }

    public boot() {
        if (this.lifecycle === 'CONSTITUTED') {
            this.transition('ACTIVE');
        }
    }

    public get State() { return this.state; }
    public get Registry() { return this.registry; }
    public get Protocols() { return this.protocols; }

    /**
     * Article V: State Interface - Propose Transition (Submit Attempt)
     */
    public submitAttempt(
        initiator: EntityID,
        protocolId: string,
        action: Action,
        cost: number = 1
    ): AttemptID {
        if (this.lifecycle !== 'ACTIVE') {
            throw new Error(`Kernel Error: Cannot submit attempt in state ${this.lifecycle}`);
        }
        const attempt: Attempt = {
            id: action.actionId,
            initiator,
            protocolId,
            action,
            cost,
            timestamp: LogicalTimestamp.fromString(action.timestamp),
            status: 'PENDING'
        };

        this.attempts.set(attempt.id, attempt);
        this.audit.append(action, 'ATTEMPT');
        return attempt.id;
    }

    /**
     * Article III.2 Authority Interface - Verify Mandate (Guard Attempt)
     */
    public guardAttempt(attemptId: AttemptID): { status: 'ACCEPTED' | 'REJECTED', reason?: string } {
        if (this.lifecycle !== 'ACTIVE') throw new Error(`Kernel Error: Cannot guard attempt in state ${this.lifecycle}`);

        const attempt = this.attempts.get(attemptId);
        if (!attempt) throw new Error("Kernel Error: Attempt not found");

        // 1. Signature Guard (Identity Resolution)
        const sigResult = SignatureGuard({ intent: attempt.action as any, manager: this.identity as any });
        if (!sigResult.ok) {
            const reason = `Authority Violation: Invalid Signature (${sigResult.violation})`;
            this.reject(attempt, reason);
            return { status: 'REJECTED', reason };
        }

        // 2. Authority Guard (Jurisdiction/Capacity check)
        const targetMetric = attempt.action.payload.metricId;
        const context = {
            time: attempt.action.timestamp,
            value: attempt.action.payload.value as number
        };

        if (!this.authority.authorized(attempt.initiator, `METRIC.WRITE:${targetMetric}`, context)) {
            const reason = `Authority Violation: ${attempt.initiator} lacks Jurisdiction or exceeds limits for ${targetMetric}`;
            const metadata = {
                initiator: attempt.initiator,
                target: targetMetric,
                context,
                violationType: 'AUTHORITY_OVERSCOPE'
            };
            this.reject(attempt, reason, metadata);
            return { status: 'REJECTED', reason };
        }

        // 3. Protocol Binding & Policy Enforcement (Product 3: Gate)
        const isSystemAction = attempt.protocolId === 'SYSTEM' || attempt.protocolId === 'ROOT';

        if (!isSystemAction) {
            if (!this.protocols.isRegistered(attempt.protocolId)) {
                const reason = "Protocol Binding Violation: Protocol not registered";
                this.reject(attempt, reason);
                return { status: 'REJECTED', reason };
            }

            // Pre-execution evaluation (The "Gate")
            const mutations = this.protocols.evaluate(attempt.timestamp, {
                metricId: attempt.action.payload.metricId,
                value: attempt.action.payload.value
            });

            const protocol = this.protocols.get(attempt.protocolId);
            if (protocol?.strict && mutations.length === 0) {
                const reason = `Policy Violation: ${protocol.name} rejects this execution.`;
                this.reject(attempt, reason, { protocolId: attempt.protocolId, violationType: 'POLICY_REJECTION' });
                return { status: 'REJECTED', reason };
            }
        }

        attempt.status = 'ACCEPTED';
        return { status: 'ACCEPTED' };
    }


    /**
     * Article V: State Interface - Commit Validated Transition
     */
    public commitAttempt(attemptId: AttemptID, budget: Budget): Commit {
        if (this.lifecycle !== 'ACTIVE') throw new Error(`Kernel Error: Cannot commit in state ${this.lifecycle}`);

        const attempt = this.attempts.get(attemptId);
        if (!attempt || attempt.status !== 'ACCEPTED') {
            throw new Error(`Kernel Error: Attempt ${attemptId} not in ACCEPTED state`);
        }

        // Article VII: Fiscal Law - Budget is equivalent to Physics
        const budResult = BudgetGuard({ budget, cost: attempt.cost });
        if (!budResult.ok) throw new Error(`Kernel Reject: Budget Violation (${budResult.violation})`);

        try {
            // 1. Protocol Execution
            const transitions: Mutation[] = [
                { metricId: attempt.action.payload.metricId, value: attempt.action.payload.value }
            ];

            const sideEffects = this.protocols.evaluate(attempt.timestamp, transitions[0]);
            transitions.push(...sideEffects);

            // 2. State Validation
            for (const t of transitions) {
                this.state.validateMutation(t);
            }

            // ATOMIC COMMIT
            budget.consume(attempt.cost);

            for (const t of transitions) {
                this.state.applyTrusted(
                    t,
                    attempt.action.timestamp,
                    transitions.indexOf(t) === 0 ? attempt.initiator : 'SYSTEM',
                    `${attempt.id}${transitions.indexOf(t) > 0 ? ':se:' + t.metricId : ''}`
                );
            }

            attempt.status = 'COMMITTED';

            // Article III.6 Institutional Ledger & Evidence
            const evidence = this.audit.append(attempt.action, 'SUCCESS');

            return {
                attemptId: attempt.id,
                oldStateHash: evidence.previousEvidenceId,
                newStateHash: evidence.evidenceId,
                cost: attempt.cost,
                timestamp: attempt.action.timestamp,
                status: 'COMMITTED'
            };

        } catch (e: any) {
            attempt.status = 'ABORTED';
            this.audit.append(attempt.action, 'ABORTED', e.message);
            throw new Error(`Kernel Halt: Commit Failed: ${e.message}`);
        }
    }

    // --- Article V: Privileged Interfaces ---

    public createEntity(actor: EntityID, params: any): void {
        this.checkGovernanceAuth(actor, 'ENTITY.CREATE');
        this.identity.register(params);
        this.audit.append(this.createSystemAction(actor, 'system.entity', params), 'SUCCESS');
    }

    public grantAuthority(actor: EntityID, granter: EntityID, grantee: EntityID, capacity: CapacityID, jurisdiction: JurisdictionID): void {
        this.checkGovernanceAuth(actor, 'AUTHORITY.GRANT');
        const timestamp = '0:0';
        const sig = 'GOVERNANCE_SIGNATURE';
        const authorityId = `auth:${Date.now()}`;

        this.authority.grant(authorityId, granter, grantee, capacity, jurisdiction, timestamp, sig);
        this.audit.append(this.createSystemAction(actor, 'system.authority', { granter, grantee, capacity, jurisdiction }), 'SUCCESS');
    }

    public revokeAuthority(actor: EntityID, authorityId: string): void {
        this.checkGovernanceAuth(actor, 'AUTHORITY.REVOKE');
        this.authority.revoke(authorityId);
        this.audit.append(this.createSystemAction(actor, 'system.revocation', { authorityId }), 'SUCCESS');
    }

    public revokeEntity(actor: EntityID, targetId: EntityID): void {
        this.checkGovernanceAuth(actor, 'ENTITY.REVOKE');
        const timestamp = '0:0';
        this.identity.revoke(targetId, timestamp);
        this.audit.append(this.createSystemAction(actor, 'system.revocation', { targetId }), 'SUCCESS');
    }

    private checkGovernanceAuth(actor: EntityID, action: string) {
        if (!this.authority.authorized(actor, `GOVERNANCE:${action}`)) {
            throw new Error(`Kernel Reject: Entity ${actor} not authorized for ${action}`);
        }
    }

    // Article V: Emergency Override (Article II.11)
    public override(action: Action, justification: string): Commit {
        if (this.lifecycle !== 'ACTIVE') throw new Error("Kernel is not ACTIVE");

        if (!this.authority.authorized(action.initiator, 'GOVERNANCE:OVERRIDE')) {
            throw new Error("Override Violation: Actor is not authorized for GOVERNANCE:OVERRIDE");
        }

        const aid = this.submitAttempt(action.initiator, 'ROOT', action);
        const attempt = this.attempts.get(aid)!;

        // Signature Guard - Mandatory (Physics of Power)
        const sigResult = SignatureGuard({ intent: attempt.action as any, manager: this.identity as any });
        if (!sigResult.ok) throw new Error(`Override Violation: Invalid Identity Signature`);

        attempt.status = 'ACCEPTED';
        this.audit.append(action, 'SUCCESS', `OVERRIDE: ${justification}`);

        return this.commitAttempt(aid, new Budget('RISK' as any, 1000));
    }

    private reject(attempt: Attempt, reason: string, metadata?: Record<string, any>) {
        attempt.status = 'REJECTED';
        this.audit.append(attempt.action, 'REJECT', reason, metadata);

        // Automatic Revocation (Product 1 requirement)
        // If a limit is breached, we pull ALL delegations for this entity on this metric (strict policy)
        if (metadata?.violationType === 'AUTHORITY_OVERSCOPE') {
            console.log(`[Iron] Breach Detected. Triggering Automatic Revocation for ${attempt.initiator}`);
            // In a real system, we'd search for the specific delegation ID. 
            // Here we'll treat it as a systemic lock on the entity for this target.
            this.identity.revoke(attempt.initiator, '0:0');
        }
    }

    private createSystemAction(initiator: EntityID, metric: string, value: any): Action {
        return {
            actionId: `sys:${Date.now()}:${Math.random()}`,
            initiator,
            payload: { metricId: metric, value },
            timestamp: '0:0',
            expiresAt: '0',
            signature: 'SYSTEM'
        };
    }

    // Article V: Execution Entry (Legacy/Direct)
    public execute(action: Action, budget?: Budget): Commit {
        const protocolId = action.payload.protocolId || 'SYSTEM';
        const aid = this.submitAttempt(action.initiator, protocolId, action);
        const guardStatus = this.guardAttempt(aid);
        if (guardStatus.status === 'REJECTED') {
            throw new Error(`Kernel Reject: ${guardStatus.reason}`);
        }
        const b = budget || new Budget('ENERGY' as any, 100);
        return this.commitAttempt(aid, b);
    }

}

