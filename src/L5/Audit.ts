
// src/L5/Audit.ts
import { hash } from '../L0/Crypto';
import { Intent } from '../L2/State';
import { StateModel } from '../L2/State';

// --- Audit Log (Hash Chain) ---
export interface LogEntry {
    hash: string;
    previousHash: string;
    intent: Intent; // Was Evidence
    status: 'SUCCESS' | 'FAILURE'; // Gap 5
}

export class AuditLog {
    private chain: LogEntry[] = [];
    private genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    public append(intent: Intent, status: 'SUCCESS' | 'FAILURE' = 'SUCCESS'): LogEntry {
        const previousHash = this.chain.length > 0 ? this.chain[this.chain.length - 1].hash : this.genesisHash;
        const entryHash = this.calculateHash(previousHash, intent, status);

        const entry: LogEntry = {
            hash: entryHash,
            previousHash: previousHash,
            intent: intent,
            status: status
        };

        this.chain.push(entry);
        return entry;
    }

    public getHistory(): LogEntry[] { return [...this.chain]; }

    private calculateHash(prevHash: string, intent: Intent, status: string): string {
        const data = prevHash + JSON.stringify(intent) + status;
        return hash(data);
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
