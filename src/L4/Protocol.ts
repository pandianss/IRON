
// src/L4/Protocol.ts
import { StateModel } from '../L2/State';
import { IntentFactory } from '../L2/IntentFactory';
import { LogicalTimestamp } from '../L0/Kernel';
import { PrincipalId } from '../L1/Identity';
import { Ed25519PrivateKey } from '../L0/Crypto';

export interface Protocol {
    id: string;
    triggerMetric: string;
    threshold: number;
    actionMetric: string;
    actionMutation: number;
}

export class ProtocolEngine {
    private protocols: Map<string, Protocol> = new Map();

    constructor(private state: StateModel) { }

    register(p: Protocol) { this.protocols.set(p.id, p); }

    evaluateAndExecute(authority: PrincipalId, privateKey: Ed25519PrivateKey, time: LogicalTimestamp) {
        // Gap 2: Conflict Detection
        // 1. Collect all triggered protocols
        const triggered: Protocol[] = [];

        for (const p of this.protocols.values()) {
            const val = Number(this.state.get(p.triggerMetric));
            if (!isNaN(val) && val > p.threshold) {
                triggered.push(p);
            }
        }

        // 2. Check for conflicts (Same Action Metric)
        const targets = new Set<string>();
        for (const p of triggered) {
            if (targets.has(p.actionMetric)) {
                throw new Error(`Protocol Conflict: Multiple protocols targeting ${p.actionMetric}`);
            }
            targets.add(p.actionMetric);
        }

        // 3. Execute Non-Conflicting Checks
        for (const p of triggered) {
            const current = Number(this.state.get(p.actionMetric) || 0);
            const newVal = current + p.actionMutation;

            const intent = IntentFactory.create(
                p.actionMetric,
                newVal,
                authority,
                privateKey
            );

            this.state.apply(intent);
        }
    }
}
