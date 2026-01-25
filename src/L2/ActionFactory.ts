// src/L2/ActionFactory.ts
import type { Action, ActionPayload } from './State.js';
import { signData, hash } from '../L0/Crypto.js';
import type { Ed25519PrivateKey } from '../L0/Crypto.js';

export class ActionFactory {
    static create(
        metricId: string,
        value: any,
        initiator: string,
        privateKey: Ed25519PrivateKey,
        timestamp: string | number = Date.now(),
        expiresAt: string | number = Date.now() + 60000,
        protocolId: string = 'SYSTEM'
    ): Action {
        const payload: ActionPayload = { protocolId, metricId, value };

        // Construct canonical data string for Signing
        const payloadStr = JSON.stringify(payload);

        // Ensure formal format "time:logical"
        const tsStr = typeof timestamp === 'string' && timestamp.includes(':')
            ? timestamp
            : `${timestamp}:0`;

        const expStr = typeof expiresAt === 'string' && expiresAt.includes(':')
            ? expiresAt
            : `${expiresAt}:0`;

        // Action ID = SHA256(Initiator + Payload + TS + Exp)
        const actionId = hash(`${initiator}:${payloadStr}:${tsStr}:${expStr}`);

        // Signature covers the Action ID as well (provenance binding)
        const signableData = `${actionId}:${initiator}:${payloadStr}:${tsStr}:${expStr}`;
        const signature = signData(signableData, privateKey);

        return {
            actionId,
            initiator,
            payload,
            timestamp: tsStr,
            expiresAt: expStr,
            signature
        };
    }
}

