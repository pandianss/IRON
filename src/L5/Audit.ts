// src/L5/Audit.ts
import { hash } from '../L0/Crypto.js';
import type { Action } from '../L2/State.js';

// --- 12. Evidence (The institutional truth substrate) ---
export interface Evidence {
    evidenceId: string; // The identifying hash
    previousEvidenceId: string; // Chain linkage
    action: Action; // LinkedAction
    status: 'SUCCESS' | 'FAILURE' | 'ATTEMPT' | 'REJECT' | 'ABORTED';
    reason?: string;
    timestamp: number; // For temporal audit
}

export class AuditLog {
    private chain: Evidence[] = [];
    private genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';

    public append(action: Action, status: 'SUCCESS' | 'FAILURE' | 'ATTEMPT' | 'REJECT' | 'ABORTED' = 'SUCCESS', reason?: string): Evidence {
        const previousHash = this.chain.length > 0 ? this.chain[this.chain.length - 1]!.evidenceId : this.genesisHash;
        const lastTs = this.chain.length > 0 ? this.chain[this.chain.length - 1]!.timestamp : 0;
        const now = Date.now();

        // IV.2 Temporal Law: Monotonicity
        if (now < lastTs) {
            throw new Error("Audit Violation: Temporal integrity breached (Time moved backwards)");
        }

        const entryHash = this.calculateHash(previousHash, action, status, now, reason);

        const evidence: Evidence = {
            evidenceId: entryHash,
            previousEvidenceId: previousHash,
            action: action,
            status: status,
            timestamp: now,
            ...(reason ? { reason } : {})
        };

        this.chain.push(evidence);
        return evidence;
    }

    public getHistory(): Evidence[] { return [...this.chain]; }

    // IV.3 Historical Legitimacy
    public verifyChain(): boolean {
        let prev = this.genesisHash;
        let lastTs = 0;

        for (const entry of this.chain) {
            // 1. Linkage Check
            if (entry.previousEvidenceId !== prev) return false;

            // 2. Hash Check
            const h = this.calculateHash(prev, entry.action, entry.status, entry.timestamp, entry.reason);
            if (h !== entry.evidenceId) return false;

            // 3. Time Check
            if (entry.timestamp < lastTs) return false;

            prev = entry.evidenceId;
            lastTs = entry.timestamp;
        }
        return true;
    }

    // Alias for compatibility
    public verifyIntegrity(): boolean { return this.verifyChain(); }

    private calculateHash(prevHash: string, action: Action, status: string, timestamp: number, reason?: string): string {
        const data = prevHash + JSON.stringify(action) + status + timestamp + (reason || '');
        return hash(data);
    }
}
