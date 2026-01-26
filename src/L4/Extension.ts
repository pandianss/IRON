
// src/L4/Extension.ts
import type { Protocol, ProtocolCategory } from './ProtocolTypes.js';

export const ALLOWED_CATEGORIES: Set<ProtocolCategory> = new Set([
    'Intent', 'Habit', 'Budget', 'Authority', 'Accountability', 'Risk', 'Continuity', 'Incapacity', 'Coordination', 'Performance', 'Intelligence'
]);

export class ExtensionValidator {
    static validate(p: Protocol): void {
        // 1. Category Check
        if (!ALLOWED_CATEGORIES.has(p.category)) {
            throw new Error(`Extension Violation: Category '${p.category}' is not allowed. Must use standard categories.`);
        }

        // 2. Structural Integrity
        if (!p.name) {
            throw new Error("Extension Violation: Protocol must have a Name.");
        }

        // 3. Invariant Relaxation Check (Heuristic)
        // "Relax Invariants" -> e.g. empty preconditions for an Intent?
        // An Intent Protocol MUST have preconditions (e.g. Signature, Expiry).
        if (p.category === 'Intent' && (!p.preconditions || p.preconditions.length === 0)) {
            throw new Error("Extension Violation: Intent Protocol must have preconditions.");
        }

        // 4. Budget Check (Existence)
        // Protocols affecting state generally should have a budget or cost.
        // Optional but recommended.
    }
}
