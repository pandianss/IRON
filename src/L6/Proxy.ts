import { GovernanceInterface, ActionBuilder } from './Interface.js';
import type { Action } from '../L2/State.js';
import type { KeyPair } from '../L0/Crypto.js';

/**
 * Product 4: Regulated Workflow Guard
 * Acts as a proxy between governance and automated workflows.
 */
export class WorkflowProxy {
    constructor(
        private governance: GovernanceInterface,
        private keyPair: KeyPair
    ) { }

    /**
     * Intercepts a workflow call.
     * @param targetName The name of the capability/metric to guard
     * @param value The value/params of the call
     * @param handler The actual code to run if authorized
     */
    public async intercept<T>(
        targetName: string,
        value: any,
        handler: () => T | Promise<T>,
        initiator: string = 'system',
        protocolId: string = 'SYSTEM'
    ): Promise<T> {
        // 1. Submit to Kernel via Interface for pre-execution check
        try {
            const builder = new ActionBuilder();
            const action = builder
                .withInitiator(initiator)
                .withProtocol(protocolId)
                .withMetric(targetName)
                .withValue(value)
                .build(this.keyPair);

            const result = await this.governance.submit(action);

            if (result.status !== 'COMMITTED') {
                throw new Error(`Governance Violation: Workflow execution blocked for ${targetName}`);
            }
        } catch (e: any) {
            throw new Error(`Governance Violation: Workflow execution blocked for ${targetName}: ${e.message}`);
        }

        // 2. Execute underlying handler ONLY if governance accepted the act
        return await handler();
    }
}
