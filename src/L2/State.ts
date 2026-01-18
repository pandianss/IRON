
// src/L2/State.ts
import { PrincipalId, IdentityManager } from '../L1/Identity';
import { verifySignature, hash } from '../L0/Crypto';
import { AuditLog } from '../L5/Audit';

// --- Intent ---
export interface MetricPayload {
    metricId: string;
    value: any;
}

export interface Intent {
    intentId: string;
    principalId: PrincipalId;
    payload: MetricPayload;
    timestamp: string;
    expiresAt: string; // BigInt or String? String due to JSON/Serialization
    signature: string;
}

// --- Metrics ---
export enum MetricType {
    COUNTER = 'COUNTER',
    GAUGE = 'GAUGE',
    BOOLEAN = 'BOOLEAN'
}

export interface MetricDefinition {
    id: string;
    description: string;
    type: MetricType;
    unit?: string;
    validator?: (value: any) => boolean;
}

export class MetricRegistry {
    private metrics: Map<string, MetricDefinition> = new Map();
    register(def: MetricDefinition) { this.metrics.set(def.id, def); }
    get(id: string) { return this.metrics.get(id); }
}

// --- State ---
export interface StateValue<T = any> {
    value: T;
    updatedAt: string; // Timestamp from Intent
    evidenceHash: string; // Link to Audit Log Entry
    stateHash: string; // SHA256(PrevStateHash + LogEntryHash)
}

export class StateModel {
    private state: Map<string, StateValue> = new Map();
    private history: Map<string, StateValue[]> = new Map();

    constructor(
        private auditLog: AuditLog,
        private registry: MetricRegistry,
        private identityManager: IdentityManager
    ) { }

    public apply(intent: Intent): void {
        try {
            // 1. Verify Identity & Signature
            const principal = this.identityManager.get(intent.principalId);
            if (!principal) throw new Error("Unknown Principal");
            if (principal.revoked) throw new Error("Principal Revoked"); // Gap 4

            const data = `${intent.intentId}:${intent.principalId}:${JSON.stringify(intent.payload)}:${intent.timestamp}:${intent.expiresAt}`;

            if (!verifySignature(data, intent.signature, principal.publicKey)) {
                throw new Error("Invalid Intent Signature");
            }

            const payload = intent.payload;
            if (!payload?.metricId) throw new Error("Missing Metric ID");

            // 2. Validate Payload
            const def = this.registry.get(payload.metricId);
            if (!def) throw new Error(`Unknown metric: ${payload.metricId}`);
            if (def.validator && !def.validator(payload.value)) throw new Error("Invalid Value");

            // 3. Gap 3: Monotonic Time Check
            const lastState = this.state.get(payload.metricId);
            if (lastState) {
                // Assuming timestamps are sortable strings (ISO) or convertible numbers
                // IntentFactory uses .toString() of Date.now(), so string comparison might fail if length differs
                // Convert to BigInt for safety
                const currentTs = BigInt(intent.timestamp);
                const lastTs = BigInt(lastState.updatedAt);

                if (currentTs < lastTs) {
                    throw new Error("Time Violation: Monotonicity Breach");
                }
            }

            // 4. Commit SUCCESS to Audit Log
            const logEntry = this.auditLog.append(intent, 'SUCCESS');

            // 5. Update State
            const prevStateHash = lastState ? lastState.stateHash : '0000000000000000000000000000000000000000000000000000000000000000';
            const stateHash = hash(prevStateHash + logEntry.hash);

            const newState: StateValue = {
                value: payload.value,
                updatedAt: intent.timestamp,
                evidenceHash: logEntry.hash,
                stateHash: stateHash
            };

            this.state.set(payload.metricId, newState);
            if (!this.history.has(payload.metricId)) this.history.set(payload.metricId, []);
            this.history.get(payload.metricId)?.push(newState);

        } catch (e: any) {
            // Gap 5: Log Failure
            // Only log if we have a halfway valid structure? 
            // If signature is bad, logging the intent might be spam.
            // But spec says "Accountability must log attempts".
            // We append with FAILURE status.
            console.warn(`State Transition Failed: ${e.message}`);
            this.auditLog.append(intent, 'FAILURE');
            throw e; // Re-throw to inform caller/sim
        }
    }

    public get(id: string) { return this.state.get(id)?.value; }
    public getHistory(id: string) { return this.history.get(id) || []; }
}
