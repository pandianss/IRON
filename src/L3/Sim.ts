
// src/L3/Sim.ts
import { StateModel, EvidenceFactory } from '../L2/State';
import { AuditLog } from '../L5/Audit';
import { MetricRegistry } from '../L2/State';
import { Budget, BudgetType } from '../L0/Kernel';

// --- Forecast Model ---
export class TrendAnalyzer {
    constructor(private state: StateModel) { }

    public forecast(metricId: string, horizon: number): number {
        const history = this.state.getHistory(metricId);
        if (history.length < 2) return 0;

        // Simple linear
        const p1 = Number(history[history.length - 2].value);
        const p2 = Number(history[history.length - 1].value);
        const slope = p2 - p1;

        return p2 + (slope * horizon);
    }
}

// --- Simulation Engine ---
export interface SimAction {
    targetMetricId: string;
    mutation: number;
}

export class SimulationEngine {
    constructor(private registry: MetricRegistry) { }

    public run(
        currentState: StateModel,
        action: SimAction,
        budget: Budget
    ): number {
        // 1. Consume Budget (Simulations aren't free)
        if (!budget.consume(1)) {
            throw new Error("Simulation Budget Exceeded");
        }

        // 2. Fork State (Mock)
        // We create ephemeral L5 Log and L2 State
        const simLog = new AuditLog();
        const simState = new StateModel(simLog, this.registry);

        // Hydrate (Simplified: just last value)
        const currentVal = currentState.get(action.targetMetricId);
        if (currentVal !== undefined) {
            // Mock history replay?
            // Just set current
            simState.apply(EvidenceFactory.create(action.targetMetricId, currentVal, 'sim', { toString: () => '0:0' } as any));
        }

        // 3. Apply Action
        const newVal = Number(currentVal || 0) + action.mutation;
        simState.apply(EvidenceFactory.create(action.targetMetricId, newVal, 'sim', { toString: () => '0:1' } as any));

        // 4. Forecast
        const analyzer = new TrendAnalyzer(simState);
        return analyzer.forecast(action.targetMetricId, 1);
    }
}
