import crypto from 'node:crypto';
import jwt, { JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';
import { createLogger } from '@kitiumai/logger';

export interface JwksKey {
  kid: string;
  publicKey: string;
  privateKey: string;
  algorithm: 'RS256' | 'ES256';
  createdAt: Date;
  expiresAt?: Date;
}

export interface KeyRotationPolicy {
  rotationDays: number;
  overlapSeconds?: number;
  enforceKid?: boolean;
}

export interface TokenFormat {
  audience: string;
  issuer: string;
  expirationSeconds: number;
  refreshExpirationSeconds?: number;
  cookieFlags?: {
    httpOnly?: boolean;
    sameSite?: 'lax' | 'strict' | 'none';
    secure?: boolean;
  };
}

export interface TokenGovernanceConfig {
  jwks: JwksKey[];
  rotation: KeyRotationPolicy;
  format: TokenFormat;
}

export interface TokenIssueResult {
  token: string;
  kid: string;
  expiresAt: Date;
}

const logger = createLogger();

export class TokenGovernance {
  private config: TokenGovernanceConfig;

  constructor(config: TokenGovernanceConfig) {
    if (config.jwks.length === 0) {
      throw new Error('At least one JWKS key is required');
    }
    this.config = config;
  }

  rotateKeys(now: Date = new Date()): JwksKey {
    const latest = this.config.jwks[this.config.jwks.length - 1]!;
    const ageDays = (now.getTime() - latest.createdAt.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < this.config.rotation.rotationDays) {
      return latest;
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const kid = crypto.randomUUID();
    const newKey: JwksKey = {
      kid,
      algorithm: 'RS256',
      publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
      privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.rotation.rotationDays * 24 * 60 * 60 * 1000),
    };

    this.config.jwks.push(newKey);
    logger.info('Rotated signing key', { kid });
    return newKey;
  }

  getActiveKey(kid?: string): JwksKey {
    if (kid) {
      const match = this.config.jwks.find((key) => key.kid === kid);
      if (!match) {
        throw new Error(`Unknown key id: ${kid}`);
      }
      return match;
    }
    return this.config.jwks[this.config.jwks.length - 1]!;
  }

  issueToken(subject: string, claims: Record<string, unknown> = {}): TokenIssueResult {
    const key = this.getActiveKey();
    const expiresAt = new Date(Date.now() + this.config.format.expirationSeconds * 1000);
    const payload: JwtPayload = {
      ...claims,
      sub: subject,
      aud: this.config.format.audience,
      iss: this.config.format.issuer,
      exp: Math.floor(expiresAt.getTime() / 1000),
      iat: Math.floor(Date.now() / 1000),
    };

    const options: SignOptions = {
      algorithm: key.algorithm,
      keyid: key.kid,
    };

    const token = jwt.sign(payload, key.privateKey, options);
    return { token, kid: key.kid, expiresAt };
  }

  verifyToken(token: string, options?: VerifyOptions): JwtPayload {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === 'string') {
      throw new Error('Invalid token');
    }
    const kid = decoded.header.kid;
    const key = this.getActiveKey(kid);

    if (this.config.rotation.enforceKid && !kid) {
      throw new Error('Missing kid header');
    }

    const payload = jwt.verify(token, key.publicKey, {
      audience: this.config.format.audience,
      issuer: this.config.format.issuer,
      algorithms: [key.algorithm],
      clockTolerance: this.config.rotation.overlapSeconds,
      ...options,
    });

    return payload as JwtPayload;
  }

  getCookieSettings(): Required<TokenFormat['cookieFlags']> {
    const { cookieFlags } = this.config.format;
    return {
      httpOnly: cookieFlags?.httpOnly ?? true,
      sameSite: cookieFlags?.sameSite ?? 'lax',
      secure: cookieFlags?.secure ?? true,
    };
  }

  getJwks(): JwksKey[] {
    return this.config.jwks;
  }
}

export function createTokenGovernance(config: Partial<TokenGovernanceConfig>): TokenGovernance {
  const now = new Date();
  const defaultKey: JwksKey = {
    kid: crypto.randomUUID(),
    algorithm: 'RS256',
    ...crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { format: 'pem', type: 'pkcs1' },
      privateKeyEncoding: { format: 'pem', type: 'pkcs1' },
    }),
    publicKey: '',
    privateKey: '',
    createdAt: now,
  } as unknown as JwksKey;

  if (!config.jwks || config.jwks.length === 0) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    defaultKey.publicKey = publicKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    defaultKey.privateKey = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
    defaultKey.expiresAt = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  }

  const format: TokenFormat = config.format ?? {
    audience: 'kitium-app',
    issuer: 'kitium-auth',
    expirationSeconds: 3600,
    cookieFlags: { httpOnly: true, sameSite: 'lax', secure: true },
  };

  const rotation: KeyRotationPolicy = config.rotation ?? {
    rotationDays: 90,
    overlapSeconds: 30,
    enforceKid: true,
  };

  return new TokenGovernance({
    jwks: config.jwks ?? [defaultKey],
    rotation,
    format,
  });
}
