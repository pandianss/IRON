// src/Chaos/Fuzzer.ts
import { ActionFactory } from '../L2/ActionFactory.js';
import { generateKeyPair } from '../L0/Crypto.js';
import type { Ed25519PrivateKey } from '../L0/Crypto.js';
import { GovernanceKernel } from '../Kernel.js';
import { IdentityManager } from '../L1/Identity.js';
import { Budget, BudgetType } from '../L0/Kernel.js';
import { SimulationEngine, MonteCarloEngine } from '../L3/Simulation.js';

export class Fuzzer {
    constructor(
        private kernel: GovernanceKernel,
        private identity: IdentityManager
    ) { }

    async run(iterations: number) {
        console.log(`Starting Fuzzing (${iterations} iterations)...`);
        // Basic loop could be added here
    }

    /**
     * Smart Fuzzing: Uses Monte Carlo to find the weak point, then attacks it.
     */
    public async runSmart(id: string, key: Ed25519PrivateKey) {
        // 1. Setup Simulation (The "Brain" of the Fuzzer)
        const sim = new SimulationEngine(this.kernel.Registry, this.kernel.Protocols);
        const mc = new MonteCarloEngine(sim);

        // 2. War Game: Find the most volatile metric
        const risk = mc.simulate(this.kernel.State, null, 20, 50, 0.2);

        console.log(`[Fuzzer] Target Identified: ${risk.metricId} (Risk: ${(risk.probabilityOfFailure * 100).toFixed(1)}%)`);

        // 3. Attack: Generate an Action that exacerbates the risk
        const mutation = risk.meanPredictedValue < 0 ? -50 : 50;

        const action = ActionFactory.create(risk.metricId, mutation, id, key);

        console.log(`[Fuzzer] Launching Smart Attack on ${risk.metricId} with val ${mutation}`);

        // 4. Execute Attack
        const aid = this.kernel.submitAttempt(id, 'SYSTEM', action);

        // 5. Observe Defense
        try {
            const guardStatus = this.kernel.guardAttempt(aid);
            if (guardStatus.status === 'ACCEPTED') {
                this.kernel.commitAttempt(aid, new Budget(BudgetType.ENERGY, 100));
                console.log(`[Fuzzer] Attack COMMITTED. System Resilience Tested.`);
            } else {
                console.log(`[Fuzzer] Attack REJECTED (Guard): ${guardStatus.reason}`);
            }
        } catch (e: any) {
            console.log(`[Fuzzer] Attack BLOCKED: ${e.message}`);
        }
    }

    public async runValid(id: string, key: Ed25519PrivateKey) {
        const action = ActionFactory.create('load', Math.random() * 100, id, key);

        const aid = this.kernel.submitAttempt(id, 'SYSTEM', action);
        const guardStatus = this.kernel.guardAttempt(aid);

        if (guardStatus.status === 'REJECTED') throw new Error(`Fuzzer Error: Valid Action Rejected by Guard: ${guardStatus.reason}`);

        this.kernel.commitAttempt(aid, new Budget(BudgetType.ENERGY, 100));
    }

    public async runInvalidSig(id: string, key: Ed25519PrivateKey) {
        const action = ActionFactory.create('load', 0, id, key);
        action.signature = 'deadbeef'; // Corrupt signature

        const aid = this.kernel.submitAttempt(id, 'SYSTEM', action);

        // Expect Guard Rejection
        const guardStatus = this.kernel.guardAttempt(aid);
        if (guardStatus.status === 'ACCEPTED') {
            throw new Error("Fuzzer Error: Invalid Signature ACCEPTED! (Authority Breach)");
        }
        // Success: System correctly rejected attack
    }

    public async runBudgetSpam(id: string, key: Ed25519PrivateKey) {
        const action = ActionFactory.create('spam', 9999, id, key);

        const aid = this.kernel.submitAttempt(id, 'SYSTEM', action, 1000000); // High cost
        const guardStatus = this.kernel.guardAttempt(aid);

        if (guardStatus.status === 'REJECTED') {
            return;
        }

        try {
            // Try to commit with small budget
            this.kernel.commitAttempt(aid, new Budget(BudgetType.ENERGY, 10));
            throw new Error("Fuzzer Error: Budget Validation Failed! (Bankruptcy)");
        } catch (e: any) {
            if (!e.message.includes("Budget")) throw e;
        }
    }
}

