import { getLogger } from '@kitiumai/logger';
import type { UserId } from '@kitiumai/types';
import { err, ok } from '@kitiumai/utils-ts/runtime/result';
import type { Result } from '@kitiumai/utils-ts/types/result';
import * as argon2 from 'argon2';
import { nanoid } from 'nanoid';
import * as speakeasy from 'speakeasy';

import { createError } from '../errors';
import type {
  BackupCode,
  SMSDevice,
  StorageAdapter,
  TOTPDevice,
  TwoFactorConfig,
  TwoFactorDevice,
  TwoFactorSession,
  TwoFactorStatus,
} from '../types';
import type { SMSProvider } from './sms-provider';
import { ConsoleSMSProvider } from './sms-provider';

/**
 * Two-Factor Authentication (2FA) Service
 * Manages TOTP, SMS, and backup code enrollment and verification with Result types
 */
export class TwoFactorAuthService {
  private readonly storage: StorageAdapter;
  private readonly config: TwoFactorConfig;
  private readonly smsProvider: SMSProvider;
  private readonly logger = getLogger();

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
   * Returns Result type for error handling
   */
  async enableTwoFactor(userId: UserId): Promise<Result<void>> {
    try {
      if (!this.config.enabled) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: '2FA is not enabled' },
          })
        );
      }

      this.logger.info('2FA enabled for user', { userId });
      // This would update user metadata
      // const user = await this.storage.getUser(userId)
      // await this.storage.updateUser(userId, {
      //   ...user,
      //   metadata: { ...user.metadata, twoFactorEnabled: true }
      // })

      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to enable 2FA', { error: String(error), userId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { userId },
        })
      );
    }
  }

  /**
   * Disable 2FA for a user
   * Returns Result type for error handling
   */
  async disableTwoFactor(userId: UserId): Promise<Result<void>> {
    try {
      if (!this.config.enabled) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: '2FA is not enabled' },
          })
        );
      }

      this.logger.info('2FA disabled for user', { userId });
      // Remove all devices for this user
      const devicesResult = await this.listDevices(userId);
      if (!devicesResult.ok) {
        return devicesResult;
      }

      const devices = devicesResult.value;
      for (const device of devices) {
        const deleteResult = await this.deleteDevice(device.id);
        if (!deleteResult.ok) {
          return deleteResult;
        }
      }

      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to disable 2FA', { error: String(error), userId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { userId },
        })
      );
    }
  }

  /**
   * Enroll a new 2FA device (TOTP)
   */
  async enrollTOTPDevice(
    userId: UserId,
    name?: string
  ): Promise<Result<TOTPDevice & { qrCode: string }>> {
    if (!this.config.enabled) {
      this.logger.warn('2FA enrollment attempted when disabled', { userId });
      return err(
        createError('auth/2fa_not_enabled', {
          context: { userId },
        })
      );
    }

    if (!this.config.methods.includes('totp')) {
      this.logger.warn('TOTP enrollment attempted when disabled', { userId });
      return err(
        createError('auth/totp_not_enabled', {
          context: { userId },
        })
      );
    }

    this.logger.debug('Enrolling TOTP device', { userId, deviceName: name });

    try {
      const secret = speakeasy.generateSecret({
        name: `${this.config.totp?.issuer || 'Kitium'} (${userId})`,
        issuer: this.config.totp?.issuer || 'Kitium',
        length: this.config.totp?.digits || 32,
      });

      const deviceId = `totp_${nanoid()}`;
      const now = new Date();
      const qrCode = secret.otpauth_url || '';

      const device: TOTPDevice = {
        id: deviceId,
        userId,
        method: 'totp',
        name,
        verified: false,
        secret: secret.base32,
        backupCodesUsed: [],
        createdAt: now,
        metadata: {
          tempSecret: secret.base32,
        },
      };

      if (!this.storage.createTwoFactorDevice) {
        return err(
          createError('auth/storage_adapter_not_supported', {
            context: { operation: 'createTwoFactorDevice' },
          })
        );
      }

      const savedDevice = await this.storage.createTwoFactorDevice(device);

      return ok({
        ...(savedDevice as TOTPDevice),
        qrCode,
      });
    } catch (error) {
      this.logger.error('Failed to enroll TOTP device', {
        error: String(error),
        userId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'enrollTOTPDevice', userId },
        })
      );
    }
  }

  /**
   * Verify TOTP device enrollment
   */
  async verifyTOTPEnrollment(
    userId: UserId,
    deviceId: string,
    code: string
  ): Promise<Result<BackupCode[]>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/2fa_not_enabled', {
          context: { userId },
        })
      );
    }

    try {
      const deviceResult = await this.getDevice(deviceId);
      if (!deviceResult.ok) {
        return deviceResult;
      }

      const device = deviceResult.value;
      if (device?.userId !== userId || device.method !== 'totp') {
        return err(
          createError('auth/device_not_found', {
            context: { deviceId, userId },
          })
        );
      }

      if (device.verified) {
        return err(
          createError('auth/device_already_verified', {
            context: { deviceId },
          })
        );
      }

      const secret = (device as TOTPDevice).secret;
      const isValidCode = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: code,
        window: 1,
      });

      if (!isValidCode) {
        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId },
          })
        );
      }

      if (this.storage.updateTwoFactorDevice) {
        await this.storage.updateTwoFactorDevice(deviceId, { verified: true });
      }

      const backupCodes = await this.generateBackupCodes(userId);
      return ok(backupCodes);
    } catch (error) {
      this.logger.error('Failed to verify TOTP enrollment', {
        error: String(error),
        userId,
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'verifyTOTPEnrollment', userId, deviceId },
        })
      );
    }
  }

  /**
   * Enroll SMS 2FA device
   */
  async enrollSMSDevice(
    userId: UserId,
    phoneNumber: string,
    name?: string
  ): Promise<Result<SMSDevice>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/2fa_not_enabled', {
          context: { userId },
        })
      );
    }

    if (!this.config.methods.includes('sms')) {
      return err(
        createError('auth/sms_not_enabled', {
          context: { userId },
        })
      );
    }

    try {
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
        return err(
          createError('auth/storage_adapter_not_supported', {
            context: { operation: 'createTwoFactorDevice' },
          })
        );
      }

      const savedDevice = await this.storage.createTwoFactorDevice(device);
      return ok(savedDevice as SMSDevice);
    } catch (error) {
      this.logger.error('Failed to enroll SMS device', {
        error: String(error),
        userId,
        phoneNumber,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'enrollSMSDevice', userId },
        })
      );
    }
  }

  /**
   * Send SMS verification code
   */
  async sendSMSCode(deviceId: string): Promise<Result<void>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/2fa_not_enabled', {
          context: { deviceId },
        })
      );
    }

    try {
      const deviceResult = await this.getDevice(deviceId);
      if (!deviceResult.ok) {
        return deviceResult;
      }

      const device = deviceResult.value;
      if (device?.method !== 'sms') {
        return err(
          createError('auth/device_not_found', {
            context: { deviceId },
          })
        );
      }

      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      await this.smsProvider.sendVerificationCode((device as SMSDevice).phoneNumber, code);

      if (this.storage.updateTwoFactorDevice) {
        await this.storage.updateTwoFactorDevice(deviceId, {
          metadata: {
            verificationCode: code,
            verificationCodeExpiresAt: expiresAt,
          },
        });
      }

      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to send SMS code', {
        error: String(error),
        deviceId,
      });
      return err(
        createError('auth/email_send_failed', {
          cause: error as Error,
          context: { operation: 'sendSMSCode', deviceId },
        })
      );
    }
  }

  /**
   * Verify SMS code
   */
  async verifySMSCode(userId: UserId, deviceId: string, code: string): Promise<Result<void>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/2fa_not_enabled', {
          context: { userId },
        })
      );
    }

    try {
      const deviceResult = await this.getDevice(deviceId);
      if (!deviceResult.ok) {
        return deviceResult;
      }

      const device = deviceResult.value;
      if (device?.userId !== userId || device.method !== 'sms') {
        return err(
          createError('auth/device_not_found', {
            context: { deviceId, userId },
          })
        );
      }

      const storedCode = device.metadata?.['verificationCode'] as string | undefined;
      const expiresAt = device.metadata?.['verificationCodeExpiresAt'] as
        | Date
        | string
        | number
        | undefined;

      if (!storedCode || !expiresAt) {
        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId },
          })
        );
      }

      const expiresAtDate = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
      if (new Date() > expiresAtDate) {
        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId, reason: 'expired' },
          })
        );
      }

      if (code !== storedCode) {
        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId },
          })
        );
      }

      if (this.storage.updateTwoFactorDevice) {
        await this.storage.updateTwoFactorDevice(deviceId, {
          verified: true,
          metadata: { verificationCode: null, verificationCodeExpiresAt: null },
        });
      }

      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to verify SMS code', {
        error: String(error),
        userId,
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'verifySMSCode', userId, deviceId },
        })
      );
    }
  }

  /**
   * Verify 2FA during authentication
   */
  async verifyTwoFactor(userId: UserId, deviceId: string, code: string): Promise<Result<boolean>> {
    if (!this.config.enabled) {
      return ok(true);
    }

    try {
      const deviceResult = await this.getDevice(deviceId);
      if (!deviceResult.ok) {
        return deviceResult;
      }

      const device = deviceResult.value;
      if (device?.userId !== userId || !device.verified) {
        return err(
          createError('auth/device_not_found', {
            context: { deviceId, userId },
          })
        );
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
          if (this.storage.updateTwoFactorDevice) {
            await this.storage.updateTwoFactorDevice(deviceId, {
              lastUsedAt: new Date(),
            });
          }
          return ok(true);
        }

        if (await this.verifyBackupCode(userId, code)) {
          return ok(true);
        }

        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId },
          })
        );
      }

      if (device.method === 'sms') {
        const storedCode = device.metadata?.['verificationCode'];
        if (code === storedCode) {
          if (this.storage.updateTwoFactorDevice) {
            await this.storage.updateTwoFactorDevice(deviceId, {
              lastUsedAt: new Date(),
            });
          }
          return ok(true);
        }

        return err(
          createError('auth/invalid_verification_code', {
            context: { deviceId },
          })
        );
      }

      return ok(false);
    } catch (error) {
      this.logger.error('Failed to verify 2FA', {
        error: String(error),
        userId,
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'verifyTwoFactor', userId, deviceId },
        })
      );
    }
  }

  /**
   * Generate backup codes
   */
  private async generateBackupCodes(userId: string): Promise<BackupCode[]> {
    const codes: BackupCode[] = [];
    const count = this.config.backup_codes_count || 10;

    for (let index = 0; index < count; index++) {
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
  async getDevice(deviceId: string): Promise<Result<TwoFactorDevice | null>> {
    if (!this.storage.getTwoFactorDevice) {
      return ok(null);
    }

    try {
      const device = await this.storage.getTwoFactorDevice(deviceId);
      return ok(device);
    } catch (error) {
      this.logger.error('Failed to get 2FA device', {
        error: String(error),
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'getDevice', deviceId },
        })
      );
    }
  }

  /**
   * List all 2FA devices for a user
   */
  async listDevices(userId: UserId): Promise<Result<TwoFactorDevice[]>> {
    if (!this.storage.listTwoFactorDevices) {
      return ok([]);
    }

    try {
      const devices = await this.storage.listTwoFactorDevices(userId);
      return ok(devices);
    } catch (error) {
      this.logger.error('Failed to list 2FA devices', {
        error: String(error),
        userId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'listDevices', userId },
        })
      );
    }
  }

  /**
   * Delete a 2FA device
   */
  async deleteDevice(deviceId: string): Promise<Result<void>> {
    if (!this.storage.deleteTwoFactorDevice) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'deleteTwoFactorDevice' },
        })
      );
    }

    try {
      await this.storage.deleteTwoFactorDevice(deviceId);
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to delete 2FA device', {
        error: String(error),
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'deleteDevice', deviceId },
        })
      );
    }
  }

  /**
   * Get 2FA status for a user
   */
  async getTwoFactorStatus(userId: UserId): Promise<Result<TwoFactorStatus>> {
    try {
      const devicesResult = await this.listDevices(userId);
      if (!devicesResult.ok) {
        return devicesResult;
      }

      const devices = devicesResult.value;
      const backupCodes = await (this.storage.getBackupCodes?.(userId) || Promise.resolve([]));
      const firstDevice = devices[0];

      return ok({
        userId,
        enabled: devices.length > 0,
        enrolledAt: firstDevice?.createdAt ?? undefined,
        devices,
        backupCodesCount: backupCodes.length,
        backupCodesUsedCount: backupCodes.filter((c) => c.used).length,
      });
    } catch (error) {
      this.logger.error('Failed to get 2FA status', {
        error: String(error),
        userId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'getTwoFactorStatus', userId },
        })
      );
    }
  }

  /**
   * Create a 2FA session for authentication flow
   */
  async createTwoFactorSession(
    userId: UserId,
    sessionId: string,
    deviceId: string
  ): Promise<Result<TwoFactorSession>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/2fa_not_enabled', {
          context: { userId },
        })
      );
    }

    try {
      const tfaSessionId = `tfa_${nanoid()}`;
      const deviceResult = await this.getDevice(deviceId);
      if (!deviceResult.ok) {
        return deviceResult;
      }

      const device = deviceResult.value;
      if (device?.userId !== userId) {
        return err(
          createError('auth/device_not_found', {
            context: { deviceId, userId },
          })
        );
      }

      const twoFactorSession: TwoFactorSession = {
        id: tfaSessionId,
        userId,
        sessionId,
        deviceId,
        method: device.method,
        attemptCount: 0,
        maxAttempts: 5,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        createdAt: new Date(),
      };

      if (!this.storage.createTwoFactorSession) {
        return err(
          createError('auth/storage_adapter_not_supported', {
            context: { operation: 'createTwoFactorSession' },
          })
        );
      }

      const result = await this.storage.createTwoFactorSession(twoFactorSession);
      return ok(result as TwoFactorSession);
    } catch (error) {
      this.logger.error('Failed to create 2FA session', {
        error: String(error),
        userId,
        deviceId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'createTwoFactorSession', userId, deviceId },
        })
      );
    }
  }

  /**
   * Complete a 2FA session
   */
  async completeTwoFactorSession(sessionId: string): Promise<Result<void>> {
    if (!this.storage.completeTwoFactorSession) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'completeTwoFactorSession' },
        })
      );
    }

    try {
      await this.storage.completeTwoFactorSession(sessionId);
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to complete 2FA session', {
        error: String(error),
        sessionId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'completeTwoFactorSession', sessionId },
        })
      );
    }
  }
}

export type {
  BackupCode,
  EnrollTwoFactorInput,
  SMSDevice,
  TOTPDevice,
  TwoFactorChallenge,
  TwoFactorConfig,
  TwoFactorDevice,
  TwoFactorSession,
  VerifyTwoFactorInput,
} from '../types';

