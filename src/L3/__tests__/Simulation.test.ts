
import { describe, test, expect, beforeEach } from '@jest/globals';
import { StateModel, MetricRegistry, MetricType } from '../../L2/State.js';
import { ProtocolEngine } from '../../L4/Protocol.js';
import { AuditLog } from '../../L5/Audit.js';
import { IdentityManager } from '../../L1/Identity.js';
import { SimulationEngine, MonteCarloEngine } from '../Simulation.js';

describe('L3 Simulation Engine (Stochastic)', () => {
    let sim: SimulationEngine;
    let monteCarlo: MonteCarloEngine;
    let state: StateModel;
    let registry: MetricRegistry;

    beforeEach(() => {
        const audit = new AuditLog();
        registry = new MetricRegistry();
        const identity = new IdentityManager();
        identity.register({
            id: 'sys',
            publicKey: 'key',
            type: 'ACTOR',
            identityProof: 'SYSTEM_GENESIS',
            status: 'ACTIVE',
            isRoot: true,
            createdAt: '0:0'
        });

        state = new StateModel(audit, registry, identity);
        const protocols = new ProtocolEngine(state);

        sim = new SimulationEngine(registry, protocols);
        monteCarlo = new MonteCarloEngine(sim);

        registry.register({ id: 'cash', description: 'Cash Flow', type: MetricType.GAUGE });
    });

    test('Monte Carlo should capture variance', () => {
        state.applyTrusted({ metricId: 'cash', value: 100 }, '0:0', 'sys');
        state.applyTrusted({ metricId: 'cash', value: 100 }, '1:0', 'sys');
        state.applyTrusted({ metricId: 'cash', value: 100 }, '2:0', 'sys');

        const action = {
            id: 'invest',
            description: 'Invest',
            targetMetricId: 'cash',
            valueMutation: 10
        };

        const risk = monteCarlo.simulate(state, action, 10, 100, 0.5);

        expect(risk.metricId).toBe('cash');
        expect(risk.meanPredictedValue).toBeGreaterThan(130);
        expect(risk.p90).not.toBe(risk.p10);
        expect(risk.p90).toBeGreaterThan(risk.p10);
    });

    test('Scenario should detect Failure Probability (Bankruptcy)', () => {
        state.applyTrusted({ metricId: 'cash', value: 10 }, '0:0', 'sys');
        state.applyTrusted({ metricId: 'cash', value: 10 }, '1:0', 'sys');

        const riskyAction = {
            id: 'gamble',
            description: 'Gamble',
            targetMetricId: 'cash',
            valueMutation: -8
        };

        const risk = monteCarlo.simulate(state, riskyAction, 1, 100, 0.5);
        expect(risk.probabilityOfFailure).toBeGreaterThan(0);
        expect(risk.probabilityOfFailure).toBeLessThan(1);
    });
});
