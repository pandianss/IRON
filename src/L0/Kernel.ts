
// src/L0/Kernel.ts
import { createHash } from 'crypto';

// --- Time ---
export interface TimeSource {
    now(): number;
}

export class SystemTime implements TimeSource {
    now(): number {
        return Date.now();
    }
}

export class LogicalTimestamp {
    constructor(public readonly time: number, public readonly logical: number) { }

    toString(): string {
        return `${this.time}:${this.logical}`;
    }

    static fromString(s: string): LogicalTimestamp {
        const [time, logical] = s.split(':').map(Number);
        return new LogicalTimestamp(time, logical);
    }
}

export class DeterministicTime {
    private lastTime = 0;
    private logicalTick = 0;
    private source: TimeSource;

    constructor(source: TimeSource = new SystemTime()) {
        this.source = source;
    }

    public getNow(): LogicalTimestamp {
        const currentWall = this.source.now();

        if (currentWall > this.lastTime) {
            this.lastTime = currentWall;
            this.logicalTick = 0;
        } else if (currentWall === this.lastTime) {
            this.logicalTick++;
        } else {
            this.logicalTick++;
        }

        return new LogicalTimestamp(this.lastTime, this.logicalTick);
    }
}

// --- Invariant ---
export class InvariantViolation extends Error {
    constructor(message: string) {
        super(`[L0-INVARIANT-VIOLATION] ${message}`);
        this.name = 'InvariantViolation';
    }
}

export class InvariantEngine {
    public static assert(condition: boolean, message: string): void {
        if (!condition) {
            throw new InvariantViolation(message);
        }
    }

    public static assertNotNull<T>(value: T | null | undefined, message: string): T {
        if (value === null || value === undefined) {
            throw new InvariantViolation(message);
        }
        return value;
    }
}

// --- Budgets ---
export enum BudgetType {
    ENERGY = 'ENERGY',
    ATTENTION = 'ATTENTION',
    RISK = 'RISK'
}

export class Budget {
    constructor(public type: BudgetType, public limit: number, public used: number = 0) { }

    public consume(amount: number): boolean {
        if (this.used + amount > this.limit) return false;
        this.used += amount;
        return true;
    }

    public reset(): void {
        this.used = 0;
    }
}
