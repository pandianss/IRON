
import { ProtocolEngine } from '../../L4/Protocol.js';
import { StateModel, MetricRegistry } from '../../L2/State.js';
import { IdentityManager } from '../../L1/Identity.js';
import { SimulationEngine } from '../../L3/Simulation.js';
import type { SimAction } from '../../L3/Simulation.js';
import { Simulation_Verification_Protocol, Adaptive_Evolution_Protocol } from './Protocols/Evolution.js';

export class IronIntelligenceInterface {
    private simEngine: SimulationEngine;

    constructor(
        private engine: ProtocolEngine,
        private state: StateModel,
        private identity: IdentityManager,
        private registry: MetricRegistry
    ) {
        this.simEngine = new SimulationEngine(this.registry, this.engine);
    }

    /**
     * Bootstraps the Intelligence system.
     */
    async initializeIntelligence() {
        if (!this.engine.isRegistered(Simulation_Verification_Protocol.id!)) {
            this.engine.propose(Simulation_Verification_Protocol);
            this.engine.ratify(Simulation_Verification_Protocol.id!, 'GOVERNANCE_SIGNATURE');
            this.engine.activate(Simulation_Verification_Protocol.id!);
        }
        if (!this.engine.isRegistered(Adaptive_Evolution_Protocol.id!)) {
            this.engine.propose(Adaptive_Evolution_Protocol);
            this.engine.ratify(Adaptive_Evolution_Protocol.id!, 'GOVERNANCE_SIGNATURE');
            this.engine.activate(Adaptive_Evolution_Protocol.id!);
        }
    }

    /**
     * Run a "What-If" Simulation.
     * Takes an action and projected horizon.
     */
    async runWhatIf(action: SimAction | null, horizon: number) {
        return this.simEngine.run(this.state, action, horizon);
    }

    /**
     * Verify a Simulation Report.
     * Legitimizes a strategy for institutional review.
     */
    async verifyStrategy(fidelityScore: number, signature: string) {
        this.state.apply({
            actionId: `str.verify.${Date.now()}`,
            initiator: 'system',
            payload: {
                metricId: 'sim.fidelity_score',
                value: fidelityScore,
                protocolId: Simulation_Verification_Protocol.id
            },
            timestamp: Date.now().toString(),
            signature: signature
        } as any);
    }

    /**
     * Propose an Evolution.
     * Based on performance data, suggest a parameter change.
     */
    async proposeEvolution(details: string, signature: string) {
        this.state.apply({
            actionId: `str.evo.${Date.now()}`,
            initiator: 'system',
            payload: {
                metricId: 'org.strategy.evolution_proposals',
                value: details,
                protocolId: Adaptive_Evolution_Protocol.id
            },
            timestamp: Date.now().toString(),
            signature: signature
        } as any);
    }
}
