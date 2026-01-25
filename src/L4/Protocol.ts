import { StateModel } from '../L2/State.js';
import { ActionFactory } from '../L2/ActionFactory.js';
import { LogicalTimestamp } from '../L0/Kernel.js';
import type { EntityID } from '../L0/Ontology.js';
import { IdentityManager } from '../L1/Identity.js';
import { verifySignature } from '../L0/Crypto.js';
import type { Ed25519PrivateKey } from '../L0/Crypto.js';
import { ExtensionValidator } from './Extension.js';
import type { Protocol, ProtocolBundle, Rule, Predicate } from './ProtocolTypes.js';
import { hash } from '../L0/Crypto.js';

export type { Protocol, ProtocolBundle };

export interface Mutation {
    metricId: string;
    value: any;
}

export class ProtocolEngine {
    private protocols: Map<string, Protocol> = new Map();

    constructor(private state: StateModel) { }

    // V.1 Creation Law: All protocols start as PROPOSED
    propose(p: Protocol): string {
        ExtensionValidator.validate(p);
        p.lifecycle = 'PROPOSED';

        // ID Generation if missing (should be deterministic based on content ideally)
        if (!p.id) p.id = hash(JSON.stringify(p));

        this.protocols.set(p.id, p);
        return p.id;
    }

    // V.1 Ratification (Requires Governance Signature)
    ratify(id: string, signature: string): void {
        const p = this.protocols.get(id);
        if (!p) throw new Error("Protocol not found");
        if (p.lifecycle !== 'PROPOSED') throw new Error(`Cannot ratify protocol in state ${p.lifecycle}`);

        // TODO: Verify signature against Governance Key (Mocked for now or passed in context)
        // verifySignature(id, signature, GOV_KEY)

        p.lifecycle = 'RATIFIED';
    }

    // V.1 Activation (Boot or Dynamic)
    activate(id: string): void {
        const p = this.protocols.get(id);
        if (!p) throw new Error("Protocol not found");
        if (p.lifecycle === 'ACTIVE') return;
        if (p.lifecycle !== 'RATIFIED') throw new Error(`Cannot activate: Protocol must be RATIFIED first (Current: ${p.lifecycle})`);

        p.lifecycle = 'ACTIVE';
    }


    // V.2 Death Law
    deprecate(id: string): void {
        const p = this.protocols.get(id);
        if (!p) return;
        p.lifecycle = 'DEPRECATED';
    }

    revoke(id: string): void {
        const p = this.protocols.get(id);
        if (!p) return;
        p.lifecycle = 'REVOKED';
    }

    isRegistered(id: string): boolean {
        return this.protocols.has(id);
    }

    get(id: string): Protocol | undefined {
        return this.protocols.get(id);
    }

    loadBundle(bundle: ProtocolBundle, trustScope: string) {
        // 1. Rule 1: Bundle ID Integrity
        const bundleCopy = { ...bundle };
        (bundleCopy as any).signature = undefined;
        (bundleCopy as any).bundleId = undefined;

        const cleanBundle = JSON.parse(JSON.stringify(bundleCopy));
        delete cleanBundle.signature;
        delete cleanBundle.bundleId;

        const sortedBundle = this.sortObject(cleanBundle);
        const stringToHash = JSON.stringify(sortedBundle);
        const calculatedId = hash(stringToHash);

        if (calculatedId !== bundle.bundleId) {
            throw new Error(`Bundle ID Mismatch: Expected ${bundle.bundleId}, calculated ${calculatedId}`);
        }

        // 2. Rule 2: Signature Verification
        let pubKey = bundle.owner.publicKey;
        if (pubKey.startsWith('ed25519:')) pubKey = pubKey.split(':')[1]!;

        let sig = bundle.signature;
        if (sig.startsWith('ed25519:')) sig = sig.split(':')[1]!;

        if (!verifySignature(calculatedId, sig, pubKey)) {
            throw new Error("Invalid Bundle Signature");
        }

        // 3. Rule 3: Owner Trust (Runtime Authority Engine check is primary)
        // Note: Commercial scope metadata removed in favor of explicit Jurisdiction primitives.
        // if (!this.isScopeAllowed(bundle.owner.scope, trustScope)) { ... }


        // 4. Rule 7: Conflict Detection
        const existingTargets = new Map<string, string>();
        for (const p of this.protocols.values()) {
            this.getActionMetrics(p).forEach(m => existingTargets.set(m, p.id!));
        }

        for (const p of bundle.protocols) {
            ExtensionValidator.validate(p);
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
            p.id = id;

            // Trusted Bundle Loading: Auto-Verify flow
            this.propose(p);
            // Bundles are considered pre-ratified by the bundle signature
            // But we must manually transition them for internal consistency
            this.ratify(id, 'BUNDLE_SIG_ALREADY_CHECKED');
            this.activate(id);
        });
    }

    private isScopeAllowed(child: string, parent: string): boolean {
        if (parent === '*') return true;
        if (child === parent) return true;
        return child.startsWith(parent + ".");
    }

    private getActionMetrics(p: Protocol): string[] {
        const metrics: string[] = [];
        for (const r of p.execution) {
            if (typeof r === 'string') continue;
            const rule = r as Rule;
            if (rule.type === 'MUTATE_METRIC' && rule.metricId) {
                metrics.push(rule.metricId);
            }
        }
        return metrics;
    }

    public evaluate(time: LogicalTimestamp, proposed?: Mutation): Mutation[] {
        const triggered: Protocol[] = [];
        const allMutations: Mutation[] = [];

        for (const p of this.protocols.values()) {
            if (p.lifecycle !== 'ACTIVE' && p.lifecycle !== 'DEPRECATED') continue;

            if (this.checkPreconditions(p, proposed)) {
                if (p.lifecycle === 'DEPRECATED') {
                    console.warn(`[Iron] Warning: Executing DEPRECATED protocol ${p.id}`);
                }
                triggered.push(p);
            }
        }

        // Rule 7: Conflict Detection (Section 5.2/3.3)
        const targets = new Set<string>();
        for (const p of triggered) {
            const metrics = this.getActionMetrics(p);
            for (const m of metrics) {
                if (targets.has(m)) throw new Error(`Protocol Conflict: Multiple protocols targeting ${m}`);
                targets.add(m);
            }
        }

        for (const p of triggered) {
            allMutations.push(...this.getRulesMutations(p, proposed));
        }

        return allMutations;
    }

    private checkPreconditions(p: Protocol, proposed?: Mutation): boolean {
        for (const pr of p.preconditions) {
            if (typeof pr === 'string') continue;
            const pre = pr as Predicate;
            if (pre.type === 'METRIC_THRESHOLD') {
                if (!pre.metricId || pre.value === undefined) continue;

                let currentVal = this.state.get(pre.metricId);
                if (proposed && proposed.metricId === pre.metricId) {
                    currentVal = proposed.value;
                }
                const current = Number(currentVal || 0);
                if (isNaN(current)) return false;

                const thresh = Number(pre.value);
                if (pre.operator === '>' && !(current > thresh)) return false;
                if (pre.operator === '>=' && !(current >= thresh)) return false;
                if (pre.operator === '<' && !(current < thresh)) return false;
                if (pre.operator === '<=' && !(current <= thresh)) return false;
                if (pre.operator === '==' && !(current === thresh)) return false;
            }
            if (pre.type === 'ALWAYS') return true;
        }
        return p.preconditions.length > 0;
    }
    private getRulesMutations(p: Protocol, proposed?: Mutation): Mutation[] {
        const mutations: Mutation[] = [];
        for (const r of p.execution) {
            if (typeof r === 'string') continue;
            const rule = r as Rule;
            if (rule.type === 'MUTATE_METRIC' && rule.metricId && rule.mutation !== undefined) {
                let currentVal = this.state.get(rule.metricId);
                if (proposed && proposed.metricId === rule.metricId) {
                    currentVal = proposed.value;
                }
                const current = Number(currentVal || 0);
                const newVal = current + rule.mutation;
                mutations.push({ metricId: rule.metricId, value: newVal });
            }
        }
        return mutations;
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

