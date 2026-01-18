
// src/L2/State.ts
import { PrincipalId, Signature } from '../L1/Identity';
import { LogicalTimestamp } from '../L0/Kernel';
import { AuditLog } from '../L5/Audit'; // Forward reference to L5 (Dependency Injection preferred)

// --- Evidence ---
export interface Evidence<T = any> {
    payload: T;
    signatory: PrincipalId;
    signature: Signature;
    timestamp: string;
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

    register(def: MetricDefinition) {
        this.metrics.set(def.id, def);
    }

    get(id: string) { return this.metrics.get(id); }
}

// --- State ---
export interface StateValue<T = any> {
    value: T;
    updatedAt: string;
    evidenceHash: string; // Link to Audit Log
}

export class StateModel {
    private state: Map<string, StateValue> = new Map();
    private history: Map<string, StateValue[]> = new Map();

    constructor(private auditLog: AuditLog, private registry: MetricRegistry) { }

    public apply(evidence: Evidence): void {
        const payload = evidence.payload;
        if (!payload?.metricId) return;

        // 1. Validate Metric
        const def = this.registry.get(payload.metricId);
        if (!def) throw new Error(`Unknown metric: ${payload.metricId}`);
        if (def.validator && !def.validator(payload.value)) throw new Error("Invalid Value");

        // 2. Commit to Audit Log (L5)
        // L2 Truth depends on L5 Audit. This circular dependency suggests they might be coupled, 
        // OR the "Kernel" of L5 (The Log) is injected here.
        const logEntry = this.auditLog.append(evidence);

        // 3. Update State
        const newState: StateValue = {
            value: payload.value,
            updatedAt: evidence.timestamp,
            evidenceHash: logEntry.hash
        };

        this.state.set(payload.metricId, newState);
        if (!this.history.has(payload.metricId)) this.history.set(payload.metricId, []);
        this.history.get(payload.metricId)?.push(newState);
    }

    public get(id: string) { return this.state.get(id)?.value; }
    public getHistory(id: string) { return this.history.get(id) || []; }
}

// --- Helper ---
export class EvidenceFactory {
    static create(metricId: string, value: any, principal: string, time: LogicalTimestamp): Evidence {
        return {
            payload: { metricId, value },
            signatory: principal,
            signature: 'sig',
            timestamp: time.toString()
        };
    }
}
