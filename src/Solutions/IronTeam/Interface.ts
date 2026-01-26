
import { ProtocolEngine } from '../../L4/Protocol.js';
import { StateModel } from '../../L2/State.js';
import { IdentityManager, AuthorityEngine } from '../../L1/Identity.js';
import { Role_Delegation_Protocol, Team_Sync_Protocol } from './Protocols/RoleDelegation.js';

export interface RoleConfig {
    id: string;
    scope: string;
    budget?: number;
    expiresAt?: string;
}

export class IronTeamInterface {
    private authEngine: AuthorityEngine;

    constructor(
        private engine: ProtocolEngine,
        private state: StateModel,
        private identity: IdentityManager
    ) {
        this.authEngine = new AuthorityEngine(this.identity);
    }

    /**
     * Bootstraps the Organization with Coordination protocols.
     */
    async initializeOrg() {
        if (!this.engine.isRegistered(Role_Delegation_Protocol.id!)) {
            this.engine.propose(Role_Delegation_Protocol);
            this.engine.ratify(Role_Delegation_Protocol.id!, 'admin-sig');
            this.engine.activate(Role_Delegation_Protocol.id!);
        }
        if (!this.engine.isRegistered(Team_Sync_Protocol.id!)) {
            this.engine.propose(Team_Sync_Protocol);
            this.engine.ratify(Team_Sync_Protocol.id!, 'admin-sig');
            this.engine.activate(Team_Sync_Protocol.id!);
        }
    }

    /**
     * Issues a Role Card (Signed Delegation).
     * This creates a node in the cryptographic Authority Map.
     */
    async issueRoleCard(
        granterId: string,
        granteeId: string,
        config: RoleConfig,
        signature: string
    ) {
        // 1. Physical Grant (L1 Authority Engine)
        // This validates the signature and record the delegation
        this.authEngine.grant(
            config.id,
            granterId,
            granteeId,
            'ROLE_HOLDER', // Fixed Capacity for Team Roles
            config.scope,
            Date.now().toString(),
            signature,
            config.expiresAt,
            config.budget ? { 'spend': config.budget } : undefined
        );

        // 2. Institutional Protocol (L4)
        // We log the issuance in the state for tracking statistics
        this.state.apply({
            actionId: `role.issue.${config.id}`,
            initiator: granterId,
            payload: {
                metricId: 'org.roles.active_count', // This is just one metric, L4 handles the rest
                value: 1,
                protocolId: Role_Delegation_Protocol.id
            },
            timestamp: Date.now().toString(),
            signature: signature
        } as any);
    }

    /**
     * Team Heartbeat.
     * Members must "Check In" to maintain Role active status.
     */
    async syncTeam(roleId: string, memberId: string, signature: string) {
        // Validate that memberId actually holds the roleId?
        // In a real system, the Protocol (L4) or Guard (L0) would check this.

        this.state.apply({
            actionId: `role.sync.${roleId}.${Date.now()}`,
            initiator: memberId,
            payload: {
                metricId: 'org.team.activity_index',
                value: 1,
                protocolId: Team_Sync_Protocol.id
            },
            timestamp: Date.now().toString(),
            signature: signature
        } as any);
    }

    /**
     * Returns the full cryptographic Authority Map (Delegation Graph).
     */
    getAuthorityMap() {
        return this.authEngine.getDelegations();
    }
}
