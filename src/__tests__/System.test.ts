
import { DeterministicTime, Budget, BudgetType } from '../L0/Kernel';
import { IdentityManager, Principal } from '../L1/Identity';
import { StateModel, MetricRegistry, MetricType, EvidenceFactory } from '../L2/State';
import { TrendAnalyzer, SimulationEngine } from '../L3/Sim';
import { ProtocolEngine } from '../L4/Protocol';
import { AuditLog, AccountabilityEngine } from '../L5/Audit';
import { GovernanceInterface } from '../L6/Interface';

describe('Iron. Closed System', () => {
    // Core Components
    let time: DeterministicTime;
    let identity: IdentityManager;
    let auditLog: AuditLog;
    let registry: MetricRegistry;
    let state: StateModel;
    let sim: SimulationEngine;
    let protocol: ProtocolEngine;
    let iface: GovernanceInterface;

    const admin: Principal = { id: 'admin', publicKey: 'k', type: 'INDIVIDUAL' };

    beforeEach(() => {
        time = new DeterministicTime();
        identity = new IdentityManager();
        identity.register(admin);

        auditLog = new AuditLog();
        registry = new MetricRegistry();
        state = new StateModel(auditLog, registry); // Inject AuditLog into State (L5 -> L2)

        registry.register({ id: 'load', description: '', type: MetricType.GAUGE });
        registry.register({ id: 'fan', description: '', type: MetricType.GAUGE });

        sim = new SimulationEngine(registry);
        protocol = new ProtocolEngine(state);
        iface = new GovernanceInterface(state, auditLog);
    });

    test('L0-L2: Evidence commits to L5 Log and updates L2 State', () => {
        const ev = EvidenceFactory.create('load', 50, admin.id, time.getNow());
        state.apply(ev);

        // Check L2
        expect(state.get('load')).toBe(50);
        // Check L5
        expect(auditLog.getHistory().length).toBe(1);
        expect(auditLog.getHistory()[0].evidence).toBe(ev);
    });

    test('L3: Simulation consumes L0 Budget', () => {
        const budget = new Budget(BudgetType.RISK, 10);

        state.apply(EvidenceFactory.create('load', 10, admin.id, time.getNow()));
        // Action: Add 10. Forecast should show increase.

        const forecast = sim.run(state, { targetMetricId: 'load', mutation: 10 }, budget);
        // 10 + 10 = 20. Forecast next step -> ??
        // Sim State history: Mock History? run() implementation sets "0:0" -> 10, "0:1" -> 20.
        // Trend: +10. Next (Horizon 1) -> 30.

        expect(forecast).toBe(30);
        expect(budget.used).toBe(1);
    });

    test('L4: Protocol triggers state change', () => {
        protocol.register({
            id: 'p1', triggerMetric: 'load', threshold: 80,
            actionMetric: 'fan', actionMutation: 100
        });

        // 1. Initial State
        state.apply(EvidenceFactory.create('load', 50, admin.id, time.getNow()));
        state.apply(EvidenceFactory.create('fan', 0, admin.id, time.getNow()));

        protocol.evaluateAndExecute(admin.id, time.getNow());
        expect(state.get('fan')).toBe(0); // No trigger

        // 2. Trigger State
        state.apply(EvidenceFactory.create('load', 90, admin.id, time.getNow()));

        protocol.evaluateAndExecute(admin.id, time.getNow());
        expect(state.get('fan')).toBe(100); // Triggered
    });
});
