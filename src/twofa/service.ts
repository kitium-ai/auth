/* eslint-disable no-restricted-imports */
import { nanoid } from 'nanoid';
import * as speakeasy from 'speakeasy';
import * as argon2 from 'argon2';
import { createLogger } from '@kitiumai/logger';
import type {
  TwoFactorConfig,
  TwoFactorDevice,
  TOTPDevice,
  SMSDevice,
  BackupCode,
  TwoFactorSession,
  TwoFactorStatus,
  StorageAdapter,
} from '../types';
import { ValidationError, AuthenticationError } from '../errors';
import { SMSProvider, ConsoleSMSProvider } from './sms-provider';

/**
 * Two-Factor Authentication (2FA) Service
 * Manages TOTP, SMS, and backup code enrollment and verification
 */
export class TwoFactorAuthService {
  private storage: StorageAdapter;
  private config: TwoFactorConfig;
  private smsProvider: SMSProvider;
  private logger = createLogger();

  constructor(
    storage: StorageAdapter,
    config: TwoFactorConfig = { enabled: false, methods: [] },
    smsProvider?: SMSProvider
  ) {
    this.storage = storage;
    this.config = config;
    this.smsProvider = smsProvider || new ConsoleSMSProvider();
    this.logger.debug('TwoFactorAuthService initialized', { enabled: config.enabled });
  }

  /**
   * Enable 2FA for a user
   */
  async enableTwoFactor(_userId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    // This would update user metadata
    // const user = await this.storage.getUser(userId)
    // await this.storage.updateUser(userId, {
    //   ...user,
    //   metadata: { ...user.metadata, twoFactorEnabled: true }
    // })
  }

  /**
   * Disable 2FA for a user
   */
  async disableTwoFactor(userId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    // Remove all devices for this user
    const devices = await this.listDevices(userId);
    for (const device of devices) {
      await this.deleteDevice(device.id);
    }
  }

  /**
   * Enroll a new 2FA device (TOTP)
   */
  async enrollTOTPDevice(userId: string, name?: string): Promise<TOTPDevice & { qrCode: string }> {
    if (!this.config.enabled) {
      this.logger.warn('2FA enrollment attempted when disabled', { userId });
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    if (!this.config.methods.includes('totp')) {
      this.logger.warn('TOTP enrollment attempted when disabled', { userId });
      throw new ValidationError({
        code: 'auth/totp_not_enabled',
        message: 'TOTP is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    this.logger.debug('Enrolling TOTP device', { userId, deviceName: name });

    const secret = speakeasy.generateSecret({
      name: `${this.config.totp?.issuer || 'Kitium'} (${userId})`,
      issuer: this.config.totp?.issuer || 'Kitium',
      length: this.config.totp?.digits || 32,
    });
    // userId is used in the secret generation above

    const deviceId = `totp_${nanoid()}`;
    const now = new Date();

    // Generate QR code and return
    const qrCode = secret.otpauth_url || '';

    const device: TOTPDevice = {
      id: deviceId,
      userId,
      method: 'totp',
      name,
      verified: false,
      secret: secret.base32, // In production, this should be encrypted
      backupCodesUsed: [],
      createdAt: now,
      metadata: {
        tempSecret: secret.base32,
      },
    };

    if (!this.storage.createTwoFactorDevice) {
      throw new ValidationError({
        code: 'auth/2fa_device_creation_not_supported',
        message: '2FA device creation is not supported',
        severity: 'error',
        retryable: false,
      });
    }

    const savedDevice = await this.storage.createTwoFactorDevice(device);

    return {
      ...(savedDevice as TOTPDevice),
      qrCode,
    };
  }

  /**
   * Verify TOTP device enrollment
   */
  async verifyTOTPEnrollment(
    userId: string,
    deviceId: string,
    code: string
  ): Promise<BackupCode[]> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    const device = await this.getDevice(deviceId);
    if (!device || device.userId !== userId || device.method !== 'totp') {
      throw new AuthenticationError({
        code: 'auth/device_not_found',
        message: 'Device not found or invalid',
        severity: 'error',
        retryable: false,
      });
    }

    if (device.verified) {
      throw new ValidationError({
        code: 'auth/device_already_verified',
        message: 'Device already verified',
        severity: 'error',
        retryable: false,
      });
    }

    // Verify TOTP code
    const secret = (device as TOTPDevice).secret;
    const isValidCode = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 1,
    });

    if (!isValidCode) {
      throw new AuthenticationError({
        code: 'auth/invalid_verification_code',
        message: 'Invalid verification code',
        severity: 'error',
        retryable: false,
      });
    }

    // Mark device as verified
    if (this.storage.getTwoFactorDevice) {
      await this.storage.updateTwoFactorDevice?.(deviceId, { verified: true });
    }

    // Generate and store backup codes
    const backupCodes = await this.generateBackupCodes(userId);

    return backupCodes;
  }

  /**
   * Enroll SMS 2FA device
   */
  async enrollSMSDevice(userId: string, phoneNumber: string, name?: string): Promise<SMSDevice> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    if (!this.config.methods.includes('sms')) {
      throw new ValidationError({
        code: 'auth/sms_not_enabled',
        message: 'SMS is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    const deviceId = `sms_${nanoid()}`;

    const device: SMSDevice = {
      id: deviceId,
      userId,
      method: 'sms',
      name,
      phoneNumber,
      verified: false,
      createdAt: new Date(),
    };

    if (!this.storage.createTwoFactorDevice) {
      throw new ValidationError({
        code: 'auth/2fa_device_creation_not_supported',
        message: '2FA device creation is not supported',
        severity: 'error',
        retryable: false,
      });
    }

    return this.storage.createTwoFactorDevice(device) as Promise<SMSDevice>;
  }

  /**
   * Send SMS verification code
   */
  async sendSMSCode(deviceId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    const device = await this.getDevice(deviceId);
    if (!device || device.method !== 'sms') {
      throw new ValidationError({
        code: 'auth/sms_device_not_found',
        message: 'SMS device not found',
        severity: 'error',
        retryable: false,
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Send SMS using configured provider
    await this.smsProvider.sendVerificationCode((device as SMSDevice).phoneNumber, code);

    // Store code in database for verification
    if (this.storage.updateTwoFactorDevice) {
      await this.storage.updateTwoFactorDevice(deviceId, {
        metadata: {
          verificationCode: code,
          verificationCodeExpiresAt: expiresAt,
        },
      });
    }
  }

  /**
   * Verify SMS code
   */
  async verifySMSCode(userId: string, deviceId: string, code: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    const device = await this.getDevice(deviceId);
    if (!device || device.userId !== userId || device.method !== 'sms') {
      throw new AuthenticationError({
        code: 'auth/device_not_found',
        message: 'Device not found or invalid',
        severity: 'error',
        retryable: false,
      });
    }

    const storedCode = device.metadata?.['verificationCode'] as string | undefined;
    const expiresAt = device.metadata?.['verificationCodeExpiresAt'] as
      | Date
      | string
      | number
      | undefined;

    if (!storedCode || !expiresAt) {
      throw new AuthenticationError({
        code: 'auth/no_verification_code',
        message: 'No verification code sent',
        severity: 'error',
        retryable: false,
      });
    }

    const expiresAtDate = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
    if (new Date() > expiresAtDate) {
      throw new AuthenticationError({
        code: 'auth/verification_code_expired',
        message: 'Verification code expired',
        severity: 'error',
        retryable: false,
      });
    }

    if (code !== storedCode) {
      throw new AuthenticationError({
        code: 'auth/invalid_verification_code',
        message: 'Invalid verification code',
        severity: 'error',
        retryable: false,
      });
    }

    // Mark device as verified
    if (this.storage.updateTwoFactorDevice) {
      await this.storage.updateTwoFactorDevice(deviceId, {
        verified: true,
        metadata: { verificationCode: null, verificationCodeExpiresAt: null },
      });
    }
  }

  /**
   * Verify 2FA during authentication
   */
  async verifyTwoFactor(userId: string, deviceId: string, code: string): Promise<boolean> {
    if (!this.config.enabled) {
      return true;
    }

    const device = await this.getDevice(deviceId);
    if (!device || device.userId !== userId || !device.verified) {
      throw new AuthenticationError({
        code: 'auth/device_not_found_or_unverified',
        message: 'Device not found or not verified',
        severity: 'error',
        retryable: false,
      });
    }

    if (device.method === 'totp') {
      const secret = (device as TOTPDevice).secret;
      const isValid = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (isValid) {
        // Update last used timestamp
        if (this.storage.updateTwoFactorDevice) {
          await this.storage.updateTwoFactorDevice(deviceId, {
            lastUsedAt: new Date(),
          });
        }
        return true;
      }

      // Check if it's a backup code
      if (await this.verifyBackupCode(userId, code)) {
        return true;
      }

      throw new AuthenticationError({
        code: 'auth/invalid_2fa_code',
        message: 'Invalid 2FA code',
        severity: 'error',
        retryable: false,
      });
    }

    if (device.method === 'sms') {
      // Verify SMS code
      const storedCode = device.metadata?.['verificationCode'];
      if (code === storedCode) {
        if (this.storage.updateTwoFactorDevice) {
          await this.storage.updateTwoFactorDevice(deviceId, {
            lastUsedAt: new Date(),
          });
        }
        return true;
      }

      throw new AuthenticationError({
        code: 'auth/invalid_2fa_code',
        message: 'Invalid 2FA code',
        severity: 'error',
        retryable: false,
      });
    }

    return false;
  }

  /**
   * Generate backup codes
   */
  private async generateBackupCodes(userId: string): Promise<BackupCode[]> {
    const codes: BackupCode[] = [];
    const count = this.config.backup_codes_count || 10;

    for (let i = 0; i < count; i++) {
      const code = nanoid(8).toUpperCase();
      const hash = await argon2.hash(code);

      codes.push({
        id: `backup_${nanoid()}`,
        userId,
        code: hash,
        used: false,
        createdAt: new Date(),
      });
    }

    // Store backup codes
    if (this.storage.createBackupCodes) {
      await this.storage.createBackupCodes(userId, codes);
    }

    return codes;
  }

  /**
   * Verify a backup code
   */
  private async verifyBackupCode(userId: string, code: string): Promise<boolean> {
    if (!this.storage.getBackupCodes) {
      return false;
    }

    const codes = await this.storage.getBackupCodes(userId);

    for (const backupCode of codes) {
      if (backupCode.used) {
        continue;
      }

      try {
        const isValid = await argon2.verify(backupCode.code, code);
        if (isValid) {
          if (this.storage.markBackupCodeUsed) {
            await this.storage.markBackupCodeUsed(backupCode.id);
          }
          return true;
        }
      } catch {
        continue;
      }
    }

    return false;
  }

  /**
   * Get a 2FA device
   */
  async getDevice(deviceId: string): Promise<TwoFactorDevice | null> {
    if (!this.storage.getTwoFactorDevice) {
      return null;
    }

    return this.storage.getTwoFactorDevice(deviceId);
  }

  /**
   * List all 2FA devices for a user
   */
  async listDevices(userId: string): Promise<TwoFactorDevice[]> {
    if (!this.storage.listTwoFactorDevices) {
      return [];
    }

    return this.storage.listTwoFactorDevices(userId);
  }

  /**
   * Delete a 2FA device
   */
  async deleteDevice(deviceId: string): Promise<void> {
    if (!this.storage.deleteTwoFactorDevice) {
      throw new ValidationError({
        code: 'auth/2fa_device_deletion_not_supported',
        message: '2FA device deletion is not supported',
        severity: 'error',
        retryable: false,
      });
    }

    return this.storage.deleteTwoFactorDevice(deviceId);
  }

  /**
   * Get 2FA status for a user
   */
  async getTwoFactorStatus(userId: string): Promise<TwoFactorStatus> {
    const devices = await this.listDevices(userId);
    const backupCodes = await (this.storage.getBackupCodes?.(userId) || Promise.resolve([]));
    const firstDevice = devices[0];

    return {
      userId,
      enabled: devices.length > 0,
      enrolledAt: firstDevice?.createdAt ?? undefined,
      devices,
      backupCodesCount: backupCodes.length,
      backupCodesUsedCount: backupCodes.filter((c) => c.used).length,
    };
  }

  /**
   * Create a 2FA session for authentication flow
   */
  async createTwoFactorSession(
    userId: string,
    sessionId: string,
    deviceId: string
  ): Promise<TwoFactorSession> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/2fa_not_enabled',
        message: '2FA is not enabled',
        severity: 'error',
        retryable: false,
      });
    }

    const tfaSessionId = `tfa_${nanoid()}`;
    const device = await this.getDevice(deviceId);

    if (!device || device.userId !== userId) {
      throw new ValidationError({
        code: 'auth/invalid_device',
        message: 'Invalid device',
        severity: 'error',
        retryable: false,
      });
    }

    const twoFactorSession: TwoFactorSession = {
      id: tfaSessionId,
      userId,
      sessionId,
      deviceId,
      method: device.method,
      attemptCount: 0,
      maxAttempts: 5,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      createdAt: new Date(),
    };

    if (!this.storage.createTwoFactorSession) {
      throw new ValidationError({
        code: 'auth/2fa_session_creation_not_supported',
        message: '2FA session creation is not supported',
        severity: 'error',
        retryable: false,
      });
    }

    const result = await this.storage.createTwoFactorSession(twoFactorSession);
    return result as TwoFactorSession;
  }

  /**
   * Complete a 2FA session
   */
  async completeTwoFactorSession(sessionId: string): Promise<void> {
    if (!this.storage.completeTwoFactorSession) {
      throw new ValidationError({
        code: 'auth/2fa_session_completion_not_supported',
        message: '2FA session completion is not supported',
        severity: 'error',
        retryable: false,
      });
    }

    return this.storage.completeTwoFactorSession(sessionId);
  }
}

export type {
  TwoFactorConfig,
  TwoFactorDevice,
  TOTPDevice,
  SMSDevice,
  BackupCode,
  TwoFactorSession,
  EnrollTwoFactorInput,
  VerifyTwoFactorInput,
  TwoFactorChallenge,
} from '../types';
