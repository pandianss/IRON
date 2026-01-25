import { DeterministicTime, InvariantEngine } from '../Kernel.js';
import { AuditLog } from '../../L5/Audit.js';
import type { Intent } from '../../L2/State.js';

describe('L0 Governance Kernel', () => {

    describe('Invariant Engine', () => {
        test('should pass when condition is true', () => {
            expect(() => InvariantEngine.assert(true, 'Should pass')).not.toThrow();
        });

        test('should throw InvariantViolation when condition is false', () => {
            expect(() => InvariantEngine.assert(false, 'Should fail')).toThrow('Should fail');
            expect(() => InvariantEngine.assert(false, 'Should fail')).toThrow(/L0-INVARIANT-VIOLATION/);
        });
    });

    describe('Deterministic Time', () => {
        test('should ensure monotonicity', () => {
            const time = new DeterministicTime();
            const t1 = time.getNow();
            const t2 = time.getNow();

            // Even if called instantly, logical tick should increment
            if (t1.time === t2.time) {
                expect(t2.logical).toBeGreaterThan(t1.logical);
            } else {
                expect(t2.time).toBeGreaterThan(t1.time);
            }
        });
    });

    describe('Audit Log', () => {
        let audit: AuditLog;

        beforeEach(() => {
            audit = new AuditLog();
        });

        test('should chain hashes correctly', () => {
            const intent1: Intent = {
                intentId: 'id1',
                principalId: 'user1',
                payload: { metricId: 'test', value: 1 },
                timestamp: '1000:0',
                expiresAt: '2000:0',
                signature: 'sig1'
            };
            const intent2: Intent = {
                intentId: 'id2',
                principalId: 'user1',
                payload: { metricId: 'test', value: 2 },
                timestamp: '1001:0',
                expiresAt: '2001:0',
                signature: 'sig2'
            };

            const entry1 = audit.append(intent1);
            const entry2 = audit.append(intent2);

            expect(entry1.previousHash).toBe('0000000000000000000000000000000000000000000000000000000000000000');
            expect(entry2.previousHash).toBe(entry1.hash);
            expect(audit.verifyIntegrity()).toBe(true);
        });

        test('should detect tampering', () => {
            const intent1: Intent = {
                intentId: 'id1',
                principalId: 'user1',
                payload: { metricId: 'test', value: 1 },
                timestamp: '1000:0',
                expiresAt: '2000:0',
                signature: 'sig1'
            };
            audit.append(intent1);
            const history = audit.getHistory();

            // Tamper with history
            (history[0]!.action.payload as any).value = 100;

            expect(audit.verifyIntegrity()).toBe(false);
        });
    });
});
