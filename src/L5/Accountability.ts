import { StateModel } from '../L2/State.js';
import { LogicalTimestamp } from '../L0/Kernel.js';
import type { EntityID } from '../L0/Ontology.js';
import { MonteCarloEngine } from '../L3/Simulation.js';

export interface SLA {
    id: string;
    metricId: string;
    min?: number;
    max?: number;
    windowTicks: number; // Duration to maintain
    incentiveAmount: number;
    penaltyAmount: number;
    maxFailureProbability?: number; // New: Risk Tolerance (0.0 - 1.0)
}

export class ObligationTracker {
    constructor(private state: StateModel) { }

    public checkCompliance(sla: SLA): boolean {
        const val = Number(this.state.get(sla.metricId));
        if (isNaN(val)) return false;

        if (sla.min !== undefined && val < sla.min) return false;
        if (sla.max !== undefined && val > sla.max) return false;

        return true;
    }
}

export class AccountabilityEngine {
    private slas: SLA[] = [];
    private tracker: ObligationTracker;

    constructor(
        private state: StateModel,
        private riskEngine?: MonteCarloEngine // Optional for now to avoid breaking tests immediately
    ) {
        this.tracker = new ObligationTracker(state);
    }

    public registerSLA(sla: SLA) {
        this.slas.push(sla);
    }

    public evaluate(entityId: EntityID, time: LogicalTimestamp) {
        this.slas.forEach(sla => {
            // 1. Check Historical Compliance (The Past)
            const isCompliant = this.tracker.checkCompliance(sla);

            // 2. Check Future Risk (The Future)
            let isRisky = false;
            let riskProb = 0;

            if (this.riskEngine && sla.maxFailureProbability !== undefined) {
                // To check risk, we need to simulate.
                // Default: Simulate "Do Nothing" (Inertia risk) 

                const risk = this.riskEngine.simulate(
                    this.state,
                    null,
                    10,
                    20,
                    0.2, // Volatility
                    (val) => {
                        // Failure Condition Closure
                        if (sla.max !== undefined && val > sla.max) return true;
                        if (sla.min !== undefined && val < sla.min) return true;
                        return false;
                    },
                    sla.metricId // Explicitly simulate the SLA metric
                );
                riskProb = risk.probabilityOfFailure;

                if (riskProb > sla.maxFailureProbability) {
                    isRisky = true;
                }
            }

            if (isCompliant && !isRisky) {
                // Safe and Compliant
                this.payout(sla.incentiveAmount, entityId, time);
            } else {
                // Penalties
                if (!isCompliant) {
                    this.penalize(sla.penaltyAmount, entityId, time, "Compliance Breach");
                }
                if (isRisky) {
                    // Risk Penalty (Pre-crime)
                    this.penalize(sla.penaltyAmount * 2, entityId, time, `High Risk Detected (${(riskProb * 100).toFixed(0)}%)`);
                }
            }
        });
    }

    private payout(amount: number, entityId: EntityID, time: LogicalTimestamp) {
        const current = Number(this.state.get('system.rewards') || 0);
        this.state.applyTrusted({ metricId: 'system.rewards', value: current + amount }, time.toString(), entityId);
    }

    private penalize(amount: number, entityId: EntityID, time: LogicalTimestamp, reason: string) {
        const current = Number(this.state.get('system.rewards') || 0);
        this.state.applyTrusted({ metricId: 'system.rewards', value: current - amount }, time.toString(), entityId);
    }
}


