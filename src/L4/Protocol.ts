
// src/L4/Protocol.ts
import { StateModel, EvidenceFactory } from '../L2/State';
import { LogicalTimestamp } from '../L0/Kernel';
import { PrincipalId } from '../L1/Identity';

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

    evaluateAndExecute(authority: PrincipalId, time: LogicalTimestamp) {
        for (const p of this.protocols.values()) {
            const val = Number(this.state.get(p.triggerMetric));
            if (!isNaN(val) && val > p.threshold) {
                // Execute
                const current = Number(this.state.get(p.actionMetric) || 0);
                const newVal = current + p.actionMutation;

                const ev = EvidenceFactory.create(p.actionMetric, newVal, authority, time);
                this.state.apply(ev);
            }
        }
    }
}
