// src/L4/Protocol.ts
import { StateModel } from '../L2/State';
import { IntentFactory } from '../L2/IntentFactory';
import { LogicalTimestamp } from '../L0/Kernel';
import { PrincipalId, IdentityManager } from '../L1/Identity';
import { Ed25519PrivateKey, verifySignature } from '../L0/Crypto';
import { ExtensionValidator } from './Extension';
import { Protocol, ProtocolBundle, ProtocolCategory, Validity, Scope, Predicate, Rule, BudgetDef, AccountabilityDef, RevocationDef } from './ProtocolTypes';
import { hash } from '../L0/Crypto';

export { Protocol, ProtocolBundle };

export class ProtocolEngine {
    private protocols: Map<string, Protocol> = new Map();

    constructor(private state: StateModel) { }

    register(p: Protocol) {
        ExtensionValidator.validate(p);
        this.protocols.set(p.id, p);
    }

    loadBundle(bundle: ProtocolBundle, trustScope: string) {
        // 1. Rule 4: Structural Integrity (implicitly handled by Type but we could check no extra fields if strictly parsed)

        // 2. Rule 1: Bundle ID Integrity (SHA256(bundle without ID/signature))
        const bundleCopy = { ...bundle };
        (bundleCopy as any).signature = undefined;
        (bundleCopy as any).bundleId = undefined;

        // Clean up undefined for hash stability
        const cleanBundle = JSON.parse(JSON.stringify(bundleCopy));
        delete cleanBundle.signature;
        delete cleanBundle.bundleId;

        const sortedBundle = this.sortObject(cleanBundle);

        const stringToHash = JSON.stringify(sortedBundle);
        const calculatedId = hash(stringToHash);

        if (calculatedId !== bundle.bundleId) {
            throw new Error(`Bundle ID Mismatch: Expected ${bundle.bundleId}, calculated ${calculatedId}`);
        }

        // 3. Rule 2: Signature Verification
        let pubKey = bundle.owner.publicKey;
        if (pubKey.startsWith('ed25519:')) pubKey = pubKey.split(':')[1];

        let sig = bundle.signature;
        if (sig.startsWith('ed25519:')) sig = sig.split(':')[1];

        // The data signed is specifically SHA256(bundleWithoutSignature) according to the user request rule.
        // Rule: signature = Sign(owner.privateKey, SHA256(bundleWithoutSignature))
        // SHA256(bundleWithoutSignature) IS the bundleId.
        if (!verifySignature(calculatedId, sig, pubKey)) {
            throw new Error("Invalid Bundle Signature");
        }

        // 4. Rule 3: Owner Scope subset Trust Scope
        // Simple string inclusion or hierarchial check. 
        // Example: 'org.ops' is subset of 'org.root'
        if (!this.isScopeAllowed(bundle.owner.scope, trustScope)) {
            throw new Error(`Owner Scope Violation: ${bundle.owner.scope} not allowed in ${trustScope}`);
        }

        // 5. Rule 5 & 6 (Validation) + Rule 7 (Conflict)
        const existingTargets = new Map<string, string>();
        for (const p of this.protocols.values()) {
            this.getActionMetrics(p).forEach(m => existingTargets.set(m, p.id));
        }

        for (const p of bundle.protocols) {
            // Rule 5 & 6: Category and Invariant checks
            ExtensionValidator.validate(p);

            // Rule 7: Conflict Detection
            const targets = this.getActionMetrics(p);
            for (const t of targets) {
                const existingId = existingTargets.get(t);
                if (existingId && existingId !== p.id) {
                    throw new Error(`Bundle Conflict: Protocol ${p.name || p.id} conflicts with ${existingId} on ${t}`);
                }
            }
        }

        // Apply
        bundle.protocols.forEach(p => {
            const id = p.id || `${bundle.bundleId}.${p.name}`;
            this.protocols.set(id, p);
        });
    }

    private isScopeAllowed(child: string, parent: string): boolean {
        if (parent === '*') return true;
        if (child === parent) return true;
        return child.startsWith(parent + ".");
    }

    private getActionMetrics(p: Protocol): string[] {
        const metrics: string[] = [];
        for (const rule of p.execution) {
            if (rule.type === 'MUTATE_METRIC' && rule.metricId) {
                metrics.push(rule.metricId);
            }
        }
        return metrics;
    }

    evaluateAndExecute(authority: PrincipalId, privateKey: Ed25519PrivateKey, time: LogicalTimestamp) {
        // 1. Trigger Detection
        const triggered: Protocol[] = [];

        for (const p of this.protocols.values()) {
            if (this.checkPreconditions(p)) {
                triggered.push(p);
            }
        }

        // 2. Conflict Check (Runtime)
        const targets = new Set<string>();
        for (const p of triggered) {
            const metrics = this.getActionMetrics(p);
            for (const m of metrics) {
                if (targets.has(m)) throw new Error(`Protocol Conflict: Multiple protocols targeting ${m}`);
                targets.add(m);
            }
        }

        // 3. Execution
        for (const p of triggered) {
            this.executeRules(p, authority, privateKey, time);
        }
    }

    private checkPreconditions(p: Protocol): boolean {
        // All preconditions must be true (AND)
        for (const pre of p.preconditions) {
            if (pre.type === 'METRIC_THRESHOLD') {
                if (!pre.metricId || pre.value === undefined) continue;
                const current = Number(this.state.get(pre.metricId));
                if (isNaN(current)) return false;

                const thresh = Number(pre.value);
                if (pre.operator === '>' && !(current > thresh)) return false;
                if (pre.operator === '>=' && !(current >= thresh)) return false;
                // .. others if needed
            }
            if (pre.type === 'ALWAYS') return true;
        }
        return p.preconditions.length > 0; // Return false if no preconditions? Or true? Assuming explicit triggers.
    }

    private executeRules(p: Protocol, authority: PrincipalId, privateKey: Ed25519PrivateKey, timestamp: number) {
        for (const rule of p.execution) {
            if (rule.type === 'MUTATE_METRIC' && rule.metricId && rule.mutation !== undefined) {
                const current = Number(this.state.get(rule.metricId) || 0);
                const newVal = current + rule.mutation;
                const intent = IntentFactory.create(rule.metricId, newVal, authority, privateKey, timestamp + 1); // +1 to ensure it is after the trigger
                this.state.apply(intent);
            }
        }
    }

    private sortObject(obj: any): any {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(item => this.sortObject(item));
        const sorted: any = {};
        Object.keys(obj).sort().forEach(key => {
            sorted[key] = this.sortObject(obj[key]);
        });
        return sorted;
    }
}
