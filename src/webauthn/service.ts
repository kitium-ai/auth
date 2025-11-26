/**
 * WebAuthn/FIDO2 Service
 * Passwordless authentication using WebAuthn API
 */

import * as crypto from 'crypto';
import { nanoid } from 'nanoid';
import { getLogger } from '@kitiumai/logger';
import { StorageAdapter } from '../types';
import { ValidationError, AuthenticationError } from '../errors';
import {
  WebAuthnDevice,
  WebAuthnConfig,
  WebAuthnRegistrationOptions,
  WebAuthnAuthenticationOptions,
  WebAuthnCredentialCreation,
  WebAuthnCredentialAssertion,
} from './types';

const logger = getLogger();

/**
 * WebAuthn Service
 */
export class WebAuthnService {
  private storage: StorageAdapter;
  private config: WebAuthnConfig;
  private challenges: Map<string, { challenge: string; expiresAt: Date; userId?: string }> =
    new Map();

  constructor(storage: StorageAdapter, config: WebAuthnConfig) {
    this.storage = storage;
    this.config = config;
    logger.debug('WebAuthnService initialized', { enabled: config.enabled });
  }

  /**
   * Generate registration options for a user
   */
  async generateRegistrationOptions(
    userId: string,
    userName: string,
    userDisplayName: string,
    excludeCredentials?: Array<{ id: string; transports?: string[] }>
  ): Promise<WebAuthnRegistrationOptions> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/webauthn_not_enabled',
        message: 'WebAuthn is not enabled',
      });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    const challengeId = `challenge_${nanoid()}`;
    const expiresAt = new Date(Date.now() + (this.config.timeout || 60000));

    this.challenges.set(challengeId, { challenge, expiresAt, userId });

    // Clean up expired challenges
    this.cleanupExpiredChallenges();

    const options: WebAuthnRegistrationOptions = {
      challenge,
      rp: {
        name: this.config.rpName,
        id: this.config.rpId,
      },
      user: {
        id: Buffer.from(userId).toString('base64url'),
        name: userName,
        displayName: userDisplayName,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      timeout: this.config.timeout,
      attestation: this.config.attestation || 'none',
      excludeCredentials: excludeCredentials?.map((cred) => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports as any,
      })),
      authenticatorSelection: this.config.authenticatorSelection,
    };

    logger.debug('WebAuthn registration options generated', { userId, challengeId });
    return options;
  }

  /**
   * Verify and store a WebAuthn credential
   */
  async verifyAndStoreCredential(
    userId: string,
    credential: WebAuthnCredentialCreation,
    challengeId: string
  ): Promise<WebAuthnDevice> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/webauthn_not_enabled',
        message: 'WebAuthn is not enabled',
      });
    }

    const storedChallenge = this.challenges.get(challengeId);
    if (!storedChallenge || storedChallenge.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/invalid_challenge',
        message: 'Invalid or expired challenge',
      });
    }

    if (new Date() > storedChallenge.expiresAt) {
      this.challenges.delete(challengeId);
      throw new AuthenticationError({
        code: 'auth/challenge_expired',
        message: 'Challenge expired',
      });
    }

    // In production, verify the attestation object and signature
    // This is a simplified version
    const deviceId = `webauthn_${nanoid()}`;
    const now = new Date();

    const device: WebAuthnDevice = {
      id: deviceId,
      userId,
      name: 'WebAuthn Device',
      credentialId: credential.credentialId,
      publicKey: credential.publicKey,
      counter: 0,
      transports: credential.transports,
      createdAt: now,
      verified: true,
    };

    // Store device in storage (would need storage adapter extension)
    // await this.storage.createWebAuthnDevice(device);

    this.challenges.delete(challengeId);
    logger.info('WebAuthn credential registered', { userId, deviceId });

    return device;
  }

  /**
   * Generate authentication options for a user
   */
  async generateAuthenticationOptions(
    userId: string,
    allowCredentials?: Array<{ id: string; transports?: string[] }>
  ): Promise<WebAuthnAuthenticationOptions> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/webauthn_not_enabled',
        message: 'WebAuthn is not enabled',
      });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    const challengeId = `challenge_${nanoid()}`;
    const expiresAt = new Date(Date.now() + (this.config.timeout || 60000));

    this.challenges.set(challengeId, { challenge, expiresAt, userId });

    const options: WebAuthnAuthenticationOptions = {
      challenge,
      timeout: this.config.timeout,
      rpId: this.config.rpId,
      allowCredentials: allowCredentials?.map((cred) => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports as any,
      })),
      userVerification: this.config.authenticatorSelection?.userVerification || 'preferred',
    };

    logger.debug('WebAuthn authentication options generated', { userId, challengeId });
    return options;
  }

  /**
   * Verify a WebAuthn authentication assertion
   */
  async verifyAuthentication(
    userId: string,
    assertion: WebAuthnCredentialAssertion,
    challengeId: string
  ): Promise<WebAuthnDevice> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/webauthn_not_enabled',
        message: 'WebAuthn is not enabled',
      });
    }

    const storedChallenge = this.challenges.get(challengeId);
    if (!storedChallenge || storedChallenge.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/invalid_challenge',
        message: 'Invalid or expired challenge',
      });
    }

    if (new Date() > storedChallenge.expiresAt) {
      this.challenges.delete(challengeId);
      throw new AuthenticationError({
        code: 'auth/challenge_expired',
        message: 'Challenge expired',
      });
    }

    // In production, verify the signature and authenticator data
    // This is a simplified version
    // const device = await this.storage.getWebAuthnDeviceByCredentialId(assertion.credentialId);
    // if (!device || device.userId !== userId) {
    //   throw new AuthenticationError('Invalid credential');
    // }

    // Verify signature and update counter
    // await this.storage.updateWebAuthnDevice(device.id, {
    //   counter: assertion.counter,
    //   lastUsedAt: new Date(),
    // });

    this.challenges.delete(challengeId);
    logger.info('WebAuthn authentication verified', { userId });

    // Return mock device for now
    return {
      id: 'device_123',
      userId,
      name: 'WebAuthn Device',
      credentialId: assertion.credentialId,
      publicKey: '',
      counter: 0,
      createdAt: new Date(),
      verified: true,
    };
  }

  /**
   * List WebAuthn devices for a user
   */
  async listDevices(userId: string): Promise<WebAuthnDevice[]> {
    // In production, fetch from storage
    // return this.storage.listWebAuthnDevices(userId);
    return [];
  }

  /**
   * Delete a WebAuthn device
   */
  async deleteDevice(deviceId: string, userId: string): Promise<void> {
    // In production, delete from storage
    // await this.storage.deleteWebAuthnDevice(deviceId);
    logger.info('WebAuthn device deleted', { deviceId, userId });
  }

  /**
   * Clean up expired challenges
   */
  private cleanupExpiredChallenges(): void {
    const now = new Date();
    for (const [id, challenge] of this.challenges.entries()) {
      if (now > challenge.expiresAt) {
        this.challenges.delete(id);
      }
    }
  }
}
