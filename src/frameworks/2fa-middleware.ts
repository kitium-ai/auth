import { Request, Response, NextFunction } from 'express';
import { getLogger } from '@kitiumai/logger';
import { TwoFactorAuthService } from '../twofa/service';
import { AuthenticationError, ValidationError } from '../errors';

/**
 * 2FA Middleware for Express.js
 * Enforces two-factor authentication for protected routes
 */

export interface TwoFAMiddlewareOptions {
  twoFAService: TwoFactorAuthService;
  skipRoutes?: string[]; // Routes that don't require 2FA
  rememberDeviceDays?: number; // Days to remember device (default: 30)
}

/**
 * Require 2FA for route access
 */
export function require2FA(options: TwoFAMiddlewareOptions) {
  const logger = getLogger();
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      if (!user || !user.id) {
        logger.warn('2FA required but user not authenticated', { path: req.path });
        throw new AuthenticationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'error',
          retryable: false,
        });
      }

      // Check if route should skip 2FA check
      if (options.skipRoutes?.some((route) => req.path.startsWith(route))) {
        return next();
      }

      // Get user's 2FA status
      const twoFAStatus = await options.twoFAService.getTwoFactorStatus(user.id);

      if (!twoFAStatus.enabled) {
        // 2FA not enrolled, skip for now (can be enforced per org)
        return next();
      }

      // Check if 2FA session is already completed
      const twoFASessionId = req.cookies?.['_tfa_session'];
      if (twoFASessionId) {
        // Verify session is still valid
        const twoFASession = await options.twoFAService.getTwoFactorSession?.(twoFASessionId);
        if (twoFASession && twoFASession.completedAt && new Date() < twoFASession.expiresAt) {
          // 2FA already completed in this session
          return next();
        }
      }

      // User requires 2FA but hasn't completed it yet
      res.status(401).json({
        error: 'Two-factor authentication required',
        code: 'TFA_REQUIRED',
        userId: user.id,
        devices: twoFAStatus.devices.map((d) => ({
          id: d.id,
          method: d.method,
          name: d.name,
          verified: d.verified,
        })),
      });
    } catch (error) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

/**
 * Verify 2FA code during authentication
 */
export function verify2FACode(options: TwoFAMiddlewareOptions) {
  const logger = getLogger();
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { userId, deviceId, code, rememberDevice } = req.body;

      if (!userId || !deviceId || !code) {
        logger.warn('2FA verification attempted with missing fields', { userId, deviceId });
        throw new ValidationError({
          code: 'auth/missing_2fa_fields',
          message: 'Missing required fields: userId, deviceId, code',
          severity: 'error',
          retryable: false,
          context: { userId, deviceId, hasCode: !!code },
        });
      }

      logger.debug('Verifying 2FA code', { userId });

      // Verify the 2FA code
      const isValid = await options.twoFAService.verifyTwoFactor(userId, deviceId, code);

      if (!isValid) {
        return res.status(401).json({
          error: 'Invalid 2FA code',
          code: 'INVALID_2FA_CODE',
        });
      }

      // Create 2FA session if verification succeeds
      const sessionId = req.cookies?.['session_id'] || `session_${Date.now()}`;
      const twoFASession = await options.twoFAService.createTwoFactorSession(
        userId,
        sessionId,
        deviceId
      );

      if (twoFASession) {
        await options.twoFAService.completeTwoFactorSession(twoFASession.id);
      }

      // Set 2FA session cookie
      const rememberDays = rememberDevice ? options.rememberDeviceDays || 30 : 0;
      const maxAge = rememberDays > 0 ? rememberDays * 24 * 60 * 60 * 1000 : undefined;

      res.cookie('_tfa_session', twoFASession?.id, {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        maxAge,
      });

      (req as any).user = {
        ...(req as any).user,
        twoFAVerified: true,
        twoFASessionId: twoFASession?.id,
        rememberDeviceUntil: rememberDays > 0 ? new Date(Date.now() + maxAge!) : undefined,
      };

      next();
    } catch (error) {
      res.status(401).json({ error: 'Failed to verify 2FA' });
    }
  };
}

/**
 * Initiate 2FA enrollment
 */
export function initiate2FAEnrollment(options: TwoFAMiddlewareOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      if (!user || !user.id) {
        throw new AuthenticationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'error',
          retryable: false,
        });
      }

      const { method, phoneNumber, name } = req.body;

      if (!method || !['totp', 'sms'].includes(method)) {
        throw new ValidationError({
          code: 'auth/invalid_2fa_method',
          message: 'Invalid 2FA method',
          severity: 'error',
          retryable: false,
          context: { method },
        });
      }

      if (method === 'sms' && !phoneNumber) {
        throw new ValidationError({
          code: 'auth/phone_number_required',
          message: 'Phone number required for SMS 2FA',
          severity: 'error',
          retryable: false,
        });
      }

      let device;
      if (method === 'totp') {
        device = await options.twoFAService.enrollTOTPDevice(user.id, name);
      } else if (method === 'sms') {
        device = await options.twoFAService.enrollSMSDevice(user.id, phoneNumber, name);
        // Send verification code
        await options.twoFAService.sendSMSCode(device.id);
      }

      res.json({
        success: true,
        device: {
          id: device.id,
          method: device.method,
          name: device.name,
          verified: device.verified,
        },
        ...(method === 'totp' && { qrCode: (device as any).qrCode }),
      });
    } catch (error) {
      res.status(400).json({ error: 'Failed to initiate 2FA enrollment' });
    }
  };
}

/**
 * Complete 2FA enrollment
 */
export function complete2FAEnrollment(options: TwoFAMiddlewareOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      if (!user || !user.id) {
        throw new AuthenticationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'error',
          retryable: false,
        });
      }

      const { deviceId, code } = req.body;

      if (!deviceId || !code) {
        throw new ValidationError({
          code: 'auth/missing_2fa_enrollment_fields',
          message: 'Missing required fields: deviceId, code',
          severity: 'error',
          retryable: false,
          context: { deviceId, hasCode: !!code },
        });
      }

      let backupCodes;
      const device = await options.twoFAService.getDevice(deviceId);

      if (device?.method === 'totp') {
        backupCodes = await options.twoFAService.verifyTOTPEnrollment(user.id, deviceId, code);
      } else if (device?.method === 'sms') {
        await options.twoFAService.verifySMSCode(user.id, deviceId, code);
      }

      res.json({
        success: true,
        device: {
          id: device?.id,
          method: device?.method,
          verified: true,
        },
        backupCodes: backupCodes?.map((bc) => ({
          id: bc.id,
          code: bc.code, // Show plaintext only once during enrollment
        })),
      });
    } catch (error) {
      res.status(400).json({ error: 'Failed to complete 2FA enrollment' });
    }
  };
}

/**
 * List user's 2FA devices
 */
export function list2FADevices(options: TwoFAMiddlewareOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      if (!user || !user.id) {
        throw new AuthenticationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'error',
          retryable: false,
        });
      }

      const devices = await options.twoFAService.listDevices(user.id);
      const status = await options.twoFAService.getTwoFactorStatus(user.id);

      res.json({
        enabled: status.enabled,
        enrolledAt: status.enrolledAt,
        devices: devices.map((d) => ({
          id: d.id,
          method: d.method,
          name: d.name,
          verified: d.verified,
          lastUsedAt: d.lastUsedAt,
        })),
        backupCodesCount: status.backupCodesCount,
        backupCodesUsedCount: status.backupCodesUsedCount,
      });
    } catch (error) {
      res.status(400).json({ error: 'Failed to list 2FA devices' });
    }
  };
}

/**
 * Delete a 2FA device
 */
export function delete2FADevice(options: TwoFAMiddlewareOptions) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      if (!user || !user.id) {
        throw new AuthenticationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'error',
          retryable: false,
        });
      }

      const { deviceId } = req.params;

      if (!deviceId) {
        throw new ValidationError({
          code: 'auth/device_id_required',
          message: 'Device ID required',
          severity: 'error',
          retryable: false,
        });
      }

      const device = await options.twoFAService.getDevice(deviceId);
      if (!device || device.userId !== user.id) {
        throw new ValidationError({
          code: 'auth/device_not_found_or_denied',
          message: 'Device not found or access denied',
          severity: 'error',
          retryable: false,
          context: { deviceId },
        });
      }

      await options.twoFAService.deleteDevice(deviceId);

      res.json({ success: true });
    } catch (error) {
      res.status(400).json({ error: 'Failed to delete 2FA device' });
    }
  };
}
