/**
 * Device Trust and Management
 * Device registration, trust, and device-based authentication
 */

import { createLogger } from '@kitiumai/logger';
import { nanoid } from 'nanoid';

import { AuthenticationError, ValidationError } from '../errors';

import type { StorageAdapter } from '../types';

const logger = createLogger();

/**
 * Device type
 */
export type DeviceType = 'desktop' | 'mobile' | 'tablet' | 'browser' | 'unknown';

/**
 * Device trust level
 */
export type DeviceTrustLevel = 'untrusted' | 'trusted' | 'verified';

/**
 * Device record
 */
export type Device = {
  id: string;
  userId: string;
  orgId?: string;
  name: string;
  type: DeviceType;
  fingerprint: string; // Device fingerprint hash
  userAgent?: string;
  ipAddress?: string;
  trustLevel: DeviceTrustLevel;
  trusted: boolean;
  verified: boolean;
  lastSeenAt: Date;
  createdAt: Date;
  metadata?: Record<string, unknown>;
};

/**
 * Device registration request
 */
export type DeviceRegistrationRequest = {
  userId: string;
  orgId?: string;
  name: string;
  fingerprint: string;
  userAgent?: string;
  ipAddress?: string;
  type?: DeviceType;
  metadata?: Record<string, unknown>;
};

/**
 * Device Management Service
 */
export class DeviceManagementService {
  private readonly devices: Map<string, Device> = new Map();

  constructor(storage: StorageAdapter) {
    logger.debug('DeviceManagementService initialized', { storageType: storage.constructor.name });
  }

  /**
   * Register a new device
   */
  async registerDevice(request: DeviceRegistrationRequest): Promise<Device> {
    const deviceId = `device_${nanoid()}`;
    const now = new Date();

    // Check if device with same fingerprint already exists
    const existingDevice = Array.from(this.devices.values()).find(
      (d) => d.fingerprint === request.fingerprint && d.userId === request.userId
    );

    if (existingDevice) {
      // Update last seen
      existingDevice.lastSeenAt = now;
      return existingDevice;
    }

    const orgId = request.orgId;
    const userAgent = request.userAgent;
    const ipAddress = request.ipAddress;
    const metadata = request.metadata;
    const device: Device = {
      id: deviceId,
      userId: request.userId,
      ...(orgId !== undefined ? { orgId } : {}),
      name: request.name,
      type: request.type || 'unknown',
      fingerprint: request.fingerprint,
      ...(userAgent !== undefined ? { userAgent } : {}),
      ...(ipAddress !== undefined ? { ipAddress } : {}),
      trustLevel: 'untrusted',
      trusted: false,
      verified: false,
      lastSeenAt: now,
      createdAt: now,
      ...(metadata !== undefined ? { metadata } : {}),
    };

    this.devices.set(deviceId, device);
    logger.info('Device registered', { deviceId, userId: request.userId });

    return device;
  }

  /**
   * Trust a device
   */
  async trustDevice(deviceId: string, userId: string): Promise<Device> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new ValidationError({
        code: 'auth/device_not_found',
        message: `Device not found: ${deviceId}`,
        severity: 'error',
        retryable: false,
        context: { deviceId },
      });
    }

    if (device.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/device_trust_unauthorized',
        message: 'Not authorized to trust this device',
        severity: 'error',
        retryable: false,
      });
    }

    device.trusted = true;
    device.trustLevel = 'trusted';
    device.lastSeenAt = new Date();

    logger.info('Device trusted', { deviceId, userId });
    return device;
  }

  /**
   * Verify a device (requires additional verification)
   */
  async verifyDevice(deviceId: string, userId: string): Promise<Device> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new ValidationError({
        code: 'auth/device_not_found',
        message: `Device not found: ${deviceId}`,
        severity: 'error',
        retryable: false,
        context: { deviceId },
      });
    }

    if (device.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/device_verify_unauthorized',
        message: 'Not authorized to verify this device',
        severity: 'error',
        retryable: false,
      });
    }

    device.verified = true;
    device.trustLevel = 'verified';
    device.lastSeenAt = new Date();

    logger.info('Device verified', { deviceId, userId });
    return device;
  }

  /**
   * Untrust a device
   */
  async untrustDevice(deviceId: string, userId: string): Promise<Device> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new ValidationError({
        code: 'auth/device_not_found',
        message: `Device not found: ${deviceId}`,
        severity: 'error',
        retryable: false,
        context: { deviceId },
      });
    }

    if (device.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/device_untrust_unauthorized',
        message: 'Not authorized to untrust this device',
        severity: 'error',
        retryable: false,
      });
    }

    device.trusted = false;
    device.verified = false;
    device.trustLevel = 'untrusted';

    logger.info('Device untrusted', { deviceId, userId });
    return device;
  }

  /**
   * Get device by ID
   */
  async getDevice(deviceId: string): Promise<Device | null> {
    return this.devices.get(deviceId) || null;
  }

  /**
   * Get device by fingerprint
   */
  async getDeviceByFingerprint(userId: string, fingerprint: string): Promise<Device | null> {
    return (
      Array.from(this.devices.values()).find(
        (d) => d.userId === userId && d.fingerprint === fingerprint
      ) || null
    );
  }

  /**
   * List devices for a user
   */
  async listDevices(userId: string, orgId?: string): Promise<Device[]> {
    return Array.from(this.devices.values())
      .filter((d) => d.userId === userId && (!orgId || d.orgId === orgId))
      .sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime());
  }

  /**
   * Delete a device
   */
  async deleteDevice(deviceId: string, userId: string): Promise<void> {
    const device = this.devices.get(deviceId);
    if (!device) {
      throw new ValidationError({
        code: 'auth/device_not_found',
        message: `Device not found: ${deviceId}`,
        severity: 'error',
        retryable: false,
        context: { deviceId },
      });
    }

    if (device.userId !== userId) {
      throw new AuthenticationError({
        code: 'auth/device_delete_unauthorized',
        message: 'Not authorized to delete this device',
        severity: 'error',
        retryable: false,
      });
    }

    this.devices.delete(deviceId);
    logger.info('Device deleted', { deviceId, userId });
  }

  /**
   * Update device last seen
   */
  async updateLastSeen(deviceId: string): Promise<void> {
    const device = this.devices.get(deviceId);
    if (device) {
      device.lastSeenAt = new Date();
    }
  }

  /**
   * Check if device is trusted
   */
  async isDeviceTrusted(deviceId: string): Promise<boolean> {
    const device = this.devices.get(deviceId);
    return device?.trusted || false;
  }

  /**
   * Check if device is verified
   */
  async isDeviceVerified(deviceId: string): Promise<boolean> {
    const device = this.devices.get(deviceId);
    return device?.verified || false;
  }

  /**
   * Generate device fingerprint from user agent and other factors
   */
  static generateFingerprint(
    userAgent: string,
    screenWidth?: number,
    screenHeight?: number,
    timezone?: string
  ): string {
    // Simplified fingerprint generation
    // In production, use a more sophisticated algorithm
    const components = [
      userAgent,
      screenWidth?.toString() || '',
      screenHeight?.toString() || '',
      timezone || '',
    ].join('|');

    // In production, use crypto.createHash('sha256')
    return Buffer.from(components).toString('base64');
  }
}
