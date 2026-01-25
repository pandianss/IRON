// src/L0/Guards.ts
import { IdentityManager, AuthorityEngine } from '../L1/Identity.js';
import { verifySignature } from './Crypto.js';
import type { Action } from '../L2/State.js';
import { Budget } from './Kernel.js';
import type { Protocol } from '../L4/Protocol.js';

// --- Guard Pattern ---
export type GuardResult = { ok: true } | { ok: false; violation: string };

export type Guard<T> = (input: T, ctx?: any) => GuardResult;

const OK: GuardResult = { ok: true };
const FAIL = (msg: string): GuardResult => ({ ok: false, violation: msg });

// --- Concrete Guards ---

// 1. Identity & Signature (Identity Resolution)
export const SignatureGuard: Guard<{ intent: Action, manager: IdentityManager }> = ({ intent, manager }) => {
    const e = manager.get(intent.initiator);
    if (!e) return FAIL("Entity not found");
    if (e.status === 'REVOKED') return FAIL("Entity revoked");

    const data = `${intent.actionId}:${intent.initiator}:${JSON.stringify(intent.payload)}:${intent.timestamp}:${intent.expiresAt}`;

    console.log(`[SignatureGuard] Data: ${data}`);
    console.log(`[SignatureGuard] Sig: ${intent.signature}`);

    if (!verifySignature(data, intent.signature, e.publicKey)) return FAIL("Invalid Signature");

    return OK;
};

// 2. Scope (Authority & Jurisdiction)
export const ScopeGuard: Guard<{
    actor: string,
    capability: string,
    engine: AuthorityEngine,
    context?: { time?: string, value?: number }
}> = ({ actor, capability, engine, context }) => {
    if (!engine.authorized(actor, capability, context)) {
        return FAIL(`Authority Violation: ${actor} lacks jurisdiction or satisfies limits for ${capability}`);
    }
    return OK;
};

// 3. Time (Monotonicity)
export const TimeGuard: Guard<{ currentTs: string, lastTs: string }> = ({ currentTs, lastTs }) => {
    // Basic monotonicity check
    if (BigInt(currentTs) < BigInt(lastTs)) return FAIL("Time Violation: Backwards timestamp");
    return OK;
};

// 4. Budget (Fiscal Law)
export const BudgetGuard: Guard<{ budget: Budget, cost: number }> = ({ budget, cost }) => {
    if ((budget.limit - budget.consumed) < cost) return FAIL("Budget Exhausted");
    return OK;
};

// 5. Protocol Conflict
export const ConflictGuard: Guard<{ protocols: Protocol[] }> = ({ protocols }) => {
    if (protocols.length > 1) {
        return FAIL("Protocol Conflict: Multiple protocols triggered");
    }
    return OK;
};

