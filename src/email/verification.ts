import { randomBytes } from 'node:crypto';

type VerificationTokenType = 'verify' | 'reset' | 'login';

export interface VerificationTokenRecord {
  token: string;
  type: VerificationTokenType;
  email?: string;
  metadata?: Record<string, unknown>;
  expiresAt: Date;
}

export interface EmailVerificationManagerOptions {
  /**
   * Base URL used when constructing verification links.
   */
  baseUrl?: string;
  /**
   * Minutes until tokens expire. Defaults to 60 minutes.
   */
  ttlMinutes?: number;
}

const DEFAULT_BASE_URL = 'http://localhost:3000';

/**
 * In-memory manager for issuing and validating email verification tokens.
 * The manager is intentionally stateful so that different frameworks can share tokens.
 */
export class EmailVerificationManager {
  private readonly tokens = new Map<string, VerificationTokenRecord>();

  constructor(private readonly options: EmailVerificationManagerOptions = {}) {}

  async generateVerificationLink(
    email?: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    const token = this.issueToken('verify', email, metadata);
    return this.buildLink('/auth/email/verify', token.token);
  }

  async generateResetLink(email?: string, metadata?: Record<string, unknown>): Promise<string> {
    const token = this.issueToken('reset', email, metadata);
    return this.buildLink('/auth/email/reset', token.token);
  }

  async generateLoginLink(email?: string, metadata?: Record<string, unknown>): Promise<string> {
    const token = this.issueToken('login', email, metadata);
    return this.buildLink('/auth/email/magic', token.token);
  }

  /**
   * Verify a token is still valid. Returns the record but does not consume it.
   */
  verifyToken(token: string, expectedType?: VerificationTokenType): VerificationTokenRecord | null {
    this.purgeExpired();
    const record = this.tokens.get(token);
    if (!record) {
      return null;
    }

    if (expectedType && record.type !== expectedType) {
      return null;
    }

    return record;
  }

  /**
   * Validate and consume a token so it cannot be reused.
   */
  consumeToken(
    token: string,
    expectedType?: VerificationTokenType
  ): VerificationTokenRecord | null {
    const record = this.verifyToken(token, expectedType);
    if (!record) {
      return null;
    }

    this.tokens.delete(token);
    return record;
  }

  private issueToken(
    type: VerificationTokenType,
    email?: string,
    metadata?: Record<string, unknown>
  ): VerificationTokenRecord {
    const token = randomBytes(32).toString('hex');
    const ttlMs = (this.options.ttlMinutes ?? 60) * 60 * 1000;
    const expiresAt = new Date(Date.now() + ttlMs);
    const record: VerificationTokenRecord = {
      token,
      type,
      email,
      metadata,
      expiresAt,
    };

    this.tokens.set(token, record);
    return record;
  }

  private buildLink(path: string, token: string): string {
    const base = (this.options.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    const url = new URL(path, base);
    url.searchParams.set('token', token);
    return url.toString();
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [token, record] of this.tokens.entries()) {
      if (record.expiresAt.getTime() <= now) {
        this.tokens.delete(token);
      }
    }
  }
}

const defaultManager = new EmailVerificationManager();

export async function generateVerificationLink(email?: string): Promise<string> {
  return defaultManager.generateVerificationLink(email);
}
export async function generateResetLink(email?: string): Promise<string> {
  return defaultManager.generateResetLink(email);
}
export async function generateLoginLink(email?: string): Promise<string> {
  return defaultManager.generateLoginLink(email);
}

export function verifyEmailToken(
  token: string,
  expectedType?: VerificationTokenType
): VerificationTokenRecord | null {
  return defaultManager.verifyToken(token, expectedType);
}
