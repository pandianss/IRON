import { DeterministicTime } from '../../L0/Kernel.js';
import { IdentityManager } from '../../L1/Identity.js';
import type { Entity } from '../../L1/Identity.js';
import { MetricRegistry, MetricType, StateModel } from '../../L2/State.js';
import { TrendAnalyzer } from '../../L2/Prediction.js';
import { AuditLog } from '../../L5/Audit.js';

describe('L1 Truth & L2 Prediction', () => {
    let audit: AuditLog;
    let time: DeterministicTime;
    let registry: MetricRegistry;
    let identity: IdentityManager;
    let state: StateModel;
    let predictor: TrendAnalyzer;
    const admin: Entity = {
        id: 'admin',
        publicKey: 'key',
        type: 'ACTOR',
        identityProof: 'TEST',
        status: 'ACTIVE',
        createdAt: '0:0'
    };

    beforeEach(() => {
        audit = new AuditLog();
        time = new DeterministicTime();
        registry = new MetricRegistry();
        identity = new IdentityManager();
        identity.register(admin);
        state = new StateModel(audit, registry, identity);
        predictor = new TrendAnalyzer(state);

        registry.register({
            id: 'system.load',
            description: 'System Load Average',
            type: MetricType.GAUGE
        });
    });

    describe('L1 Truth', () => {
        test('should update state from trusted source', () => {
            state.applyTrusted({ metricId: 'system.load', value: 0.5 }, time.getNow().toString(), admin.id);

            expect(state.get('system.load')).toBe(0.5);
            expect(audit.getHistory().length).toBe(1);
        });

        test('should maintain history', () => {
            state.applyTrusted({ metricId: 'system.load', value: 0.5 }, time.getNow().toString(), admin.id);
            state.applyTrusted({ metricId: 'system.load', value: 0.6 }, time.getNow().toString(), admin.id);

            const history = state.getHistory('system.load');
            expect(history.length).toBe(2);
            expect(history[0]!.value).toBe(0.5);
            expect(history[1]!.value).toBe(0.6);
        });
    });

    describe('L2 Prediction', () => {
        test('should forecast linear trend', () => {
            // Seed 0, 10, 20, 30...
            state.applyTrusted({ metricId: 'system.load', value: 0 }, time.getNow().toString(), admin.id);
            state.applyTrusted({ metricId: 'system.load', value: 10 }, time.getNow().toString(), admin.id);
            state.applyTrusted({ metricId: 'system.load', value: 20 }, time.getNow().toString(), admin.id);

            const forecast = predictor.forecast('system.load', 1);

            expect(forecast).not.toBeNull();
            expect(forecast!.predictedValue).toBeCloseTo(30);
        });

        test('should calculate confidence bands', () => {
            // Perfect line -> 0 deviation
            state.applyTrusted({ metricId: 'system.load', value: 0 }, time.getNow().toString(), admin.id);
            state.applyTrusted({ metricId: 'system.load', value: 10 }, time.getNow().toString(), admin.id);

            const forecast = predictor.forecast('system.load', 1);
            expect(forecast!.confidenceHigh).toBeCloseTo(20);
            expect(forecast!.confidenceLow).toBeCloseTo(20);

            // Noisy data
            state.applyTrusted({ metricId: 'system.load', value: 22 }, time.getNow().toString(), admin.id);

            const noisyForecast = predictor.forecast('system.load', 1);

            expect(noisyForecast!.confidenceHigh).toBeGreaterThan(noisyForecast!.confidenceLow);
        });
    });
});

