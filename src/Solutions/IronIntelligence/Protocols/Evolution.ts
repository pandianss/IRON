
import type { Protocol } from '../../../../L4/ProtocolTypes.js';

/**
 * Iron Intelligence: Simulation Verification Protocol
 * Governs the validation of sandbox simulations before institutional acceptance.
 */
export const Simulation_Verification_Protocol: Protocol = {
    id: 'iron.intelligence.sim.verify.v1',
    name: "Simulation Integrity Verification",
    version: "1.0.0",
    category: "Intelligence",
    lifecycle: "PROPOSED",
    strict: true,

    preconditions: [
        {
            type: "METRIC_THRESHOLD",
            metricId: "sim.fidelity_score",
            operator: ">=",
            value: 90 // High fidelity required for verification
        }
    ],

    execution: [
        {
            type: "MUTATE_METRIC",
            metricId: "org.strategy.verified_scenarios",
            mutation: 1
        },
        {
            type: "MUTATE_METRIC",
            metricId: "user.gamification.xp",
            mutation: 25 // High reward for strategic modeling
        }
    ]
};

/**
 * Iron Intelligence: Adaptive Evolution Protocol
 * Governs the suggestion of optimized protocol parameters.
 */
export const Adaptive_Evolution_Protocol: Protocol = {
    id: 'iron.intelligence.evo.suggest.v1',
    name: "Adaptive Protocol Evolution",
    version: "1.0.0",
    category: "Intelligence",
    lifecycle: "PROPOSED",
    strict: true,

    preconditions: [
        {
            type: "METRIC_THRESHOLD",
            metricId: "org.kpi.total_velocity",
            operator: ">",
            value: 100 // Evolution suggested during high throughput periods
        }
    ],

    execution: [
        {
            type: "MUTATE_METRIC",
            metricId: "org.strategy.evolution_proposals",
            mutation: 1
        }
    ]
};
