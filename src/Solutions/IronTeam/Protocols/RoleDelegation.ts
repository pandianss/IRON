
import type { Protocol } from '../../../../L4/ProtocolTypes.js';

/**
 * Iron Team: Role Delegation Protocol
 * Governs the issuance of "Role Cards" (Signed Delegations).
 */
export const Role_Delegation_Protocol: Protocol = {
    id: 'iron.team.coordination.role.v1',
    name: "Role Card Issuance",
    version: "1.0.0",
    category: "Coordination",
    lifecycle: "PROPOSED",
    strict: true,

    // Logic: Valid Delegation Request
    preconditions: [
        // 1. Signature Check is performed by L1 Identity/Authority Engine.
        // 2. We can add institutional rules here, e.g. "Budget Limit"
        {
            type: "METRIC_THRESHOLD",
            metricId: "org.budget.total_allocated",
            operator: "<=",
            value: 1000000 // Sample Hard Ceiling for total org allocation
        }
    ],

    execution: [
        // 1. Log the Role Issuance
        {
            type: "MUTATE_METRIC",
            metricId: "org.roles.active_count",
            mutation: 1
        },
        // 2. Track Team Health (Initially 100)
        {
            type: "MUTATE_METRIC",
            metricId: "org.team.health",
            mutation: 100 // Reset/Init health for new role node
        }
    ]
};

/**
 * Iron Team: Sync Protocol (Heartbeat)
 * Governs the "Check-In" rhythm of roles.
 */
export const Team_Sync_Protocol: Protocol = {
    id: 'iron.team.coordination.sync.v1',
    name: "Team Cadence Sync",
    version: "1.0.0",
    category: "Coordination",
    lifecycle: "PROPOSED",
    strict: true,

    preconditions: [
        {
            type: "ALWAYS",
            value: true
        }
    ],

    execution: [
        // 1. Update Health on successful sync
        {
            type: "MUTATE_METRIC",
            metricId: "org.team.health",
            mutation: 10 // Bonus for sync
        },
        // 2. Log activity
        {
            type: "MUTATE_METRIC",
            metricId: "org.team.activity_index",
            mutation: 1
        }
    ]
};
