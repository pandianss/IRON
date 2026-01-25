
import { StateModel } from '../L2/State.js';
import { ActionFactory } from '../L2/ActionFactory.js';
import { LogicalTimestamp } from '../L0/Kernel.js';
import type { EntityID } from '../L0/Ontology.js';
import { SimulationEngine } from '../L3/Simulation.js';
import type { SimAction } from '../L3/Simulation.js';

export class ChaosBudget {
    constructor(private limit: number, private currentSpend: number = 0) { }

    public canAfford(cost: number): boolean {
        return (this.currentSpend + cost) <= this.limit;
    }

    public spend(cost: number) {
        this.currentSpend += cost;
    }

    public reset() {
        this.currentSpend = 0;
    }

    public getRemaining(): number {
        return this.limit - this.currentSpend;
    }
}

export class ChaosEngine {
    private budget: ChaosBudget;

    constructor(
        private state: StateModel,
        budgetLimit: number = 100
    ) {
        this.budget = new ChaosBudget(budgetLimit);
    }

    public scheduleInjection(
        action: SimAction,
        cost: number,
        entityId: EntityID,
        time: LogicalTimestamp
    ): boolean {
        // 1. Check Safety (Circuit Breaker)
        if (!this.isSystemStable()) {
            console.warn("Chaos aborted: System unstable.");
            return false;
        }

        // 2. Check Budget
        if (!this.budget.canAfford(cost)) {
            console.warn("Chaos aborted: Budget exceeded.");
            return false;
        }

        // 3. Inject (Apply Action)
        this.budget.spend(cost);
        this.executeChaos(action, entityId, time);
        return true;
    }

    private isSystemStable(): boolean {
        // Simple health check. MVP: load < 90?
        const load = Number(this.state.get('system.load') || 0);
        return load < 90;
    }

    private executeChaos(action: SimAction, entityId: EntityID, time: LogicalTimestamp) {
        // Reuse similar logic to L3/L4 appliers
        const currentVal = Number(this.state.get(action.targetMetricId) || 0);
        const newVal = currentVal + action.valueMutation;

        // Using applyTrusted for internal chaos injection
        this.state.applyTrusted({ metricId: action.targetMetricId, value: newVal }, time.toString(), entityId);
    }
}

