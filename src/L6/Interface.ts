import { StateModel } from '../L2/State.js';
import type { Action, ActionPayload } from '../L2/State.js';
import { AuditLog } from '../L5/Audit.js';
import { signData, hash } from '../L0/Crypto.js';
import type { KeyPair } from '../L0/Crypto.js';
import { GovernanceKernel } from '../Kernel.js';
import { Budget, BudgetType } from '../L0/Kernel.js';
import type { EntityID } from '../L0/Ontology.js';

/**
 * 6. Interface (Constitutional Interface)
 */
export class GovernanceInterface {
    constructor(
        private kernel: GovernanceKernel,
        private state: StateModel,
        private log: AuditLog
    ) { }

    public getTruth(id: string) { return this.state.get(id); }

    public getAuditTrail(id: string) {
        return this.log.getHistory()
            .filter(e => e.action.payload.metricId === id)
            .map(e => ({
                value: e.action.payload.value,
                timestamp: e.action.timestamp,
                proof: e.evidenceId
            }));
    }

    // The Single Door: All Writes must go through Kernel (Article VII)
    public submit(action: Action, options: { budgetLimit?: number } = {}) {
        const budget = new Budget(BudgetType.ENERGY, options.budgetLimit || 100);
        return this.kernel.execute(action, budget);
    }

    /**
     * Product 2: Governance Breach Monitor
     * Extracts structured violation data from the Audit Log.
     */
    public getBreachReports() {
        return this.log.getHistory()
            .filter(e => e.status === 'REJECT' || e.status === 'ABORTED')
            .map(e => ({
                actionId: e.action.actionId,
                initiator: e.action.initiator,
                reason: e.reason,
                metadata: e.metadata,
                timestamp: e.timestamp
            }));
    }

    /**
     * Product 2: Incident Reconstruction
     * Groups related evidence by context (e.g., metric, initiator).
     */
    public reconstructIncident(actionId: string) {
        const history = this.log.getHistory();
        const mainEntry = history.find(e => e.action.actionId === actionId);
        if (!mainEntry) return null;

        return {
            incident: mainEntry,
            timeline: history.filter(e =>
                e.action.initiator === mainEntry.action.initiator &&
                e.timestamp <= mainEntry.timestamp
            ).slice(-5) // Last 5 steps leadings to breach
        };
    }
}

// --- VI.1 Consent Law (Action Builder) ---
export class ActionBuilder {
    private initiator: EntityID = '';
    private protocolId: string = 'SYSTEM';
    private metricId: string = '';
    private value: any = null;
    private expiresAt: string = '0:0';
    private timestamp: string = '';

    private context: string = '';

    constructor() { }

    public withInitiator(id: EntityID): this { this.initiator = id; return this; }
    public withProtocol(id: string): this { this.protocolId = id; return this; }
    public withMetric(id: string): this { this.metricId = id; return this; }
    public withValue(val: any): this { this.value = val; return this; }

    // Binding the UI/Human Context to the Action (For Audit Evidence)
    public withContext(uiLabel: string, workflowId: string): this {
        this.context = `${uiLabel}::${workflowId}`;
        return this;
    }

    public build(keyPair: KeyPair): Action {
        if (!this.initiator || !this.metricId) throw new Error("Incomplete Action");

        this.timestamp = `${Date.now()}:0`;
        const payload: ActionPayload = { protocolId: this.protocolId, metricId: this.metricId, value: this.value };

        // Action ID = SHA256(Initiator + Payload + TS + Exp)
        const actionId = hash(`${this.initiator}:${JSON.stringify(payload)}:${this.timestamp}:${this.expiresAt}`);

        // Signature must match Kernel's validation string
        const data = `${actionId}:${this.initiator}:${JSON.stringify(payload)}:${this.timestamp}:${this.expiresAt}`;
        const signature = signData(data, keyPair.privateKey);

        return {
            actionId,
            initiator: this.initiator,
            payload,
            timestamp: this.timestamp,
            expiresAt: this.expiresAt,
            signature
        };
    }
}

// --- XI. Override (Primitive 11) ---
export interface OverrideAction {
    type: 'OVERRIDE';
    targetActionId: string;
    justification: string;
    signature: string;
}



