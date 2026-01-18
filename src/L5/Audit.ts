
// src/L5/Audit.ts
import { createHash } from 'crypto';
import { Evidence } from '../L2/State'; // Circular Type? Interface Only.
import { StateModel } from '../L2/State'; // For Accountability execution

// --- Audit Log (Hash Chain) ---
export interface LogEntry {
    hash: string;
    previousHash: string;
    evidence: Evidence;
}

export class AuditLog {
    private chain: LogEntry[] = [];
    private genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    public append(evidence: Evidence): LogEntry {
        const previousHash = this.chain.length > 0 ? this.chain[this.chain.length - 1].hash : this.genesisHash;
        const hash = this.calculateHash(previousHash, evidence);

        const entry: LogEntry = {
            hash,
            previousHash,
            evidence
        };

        this.chain.push(entry);
        return entry;
    }

    public getHistory(): LogEntry[] { return [...this.chain]; }

    private calculateHash(prevHash: string, evidence: Evidence): string {
        const data = prevHash + JSON.stringify(evidence);
        return createHash('sha256').update(data).digest('hex');
    }
}

// --- Accountability ---
export interface SLA {
    id: string;
    metricId: string;
    min?: number;
    max?: number;
    incentiveAmount: number;
    penaltyAmount: number;
}

export class AccountabilityEngine {
    constructor(private state: StateModel) { } // Depends on L2 State to read Truth

    public checkSLA(sla: SLA): number {
        const val = Number(this.state.get(sla.metricId));
        if (isNaN(val)) return 0;

        if (sla.min !== undefined && val < sla.min) return -sla.penaltyAmount;
        if (sla.max !== undefined && val > sla.max) return -sla.penaltyAmount;

        return sla.incentiveAmount;
    }
}
