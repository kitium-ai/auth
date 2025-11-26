/* eslint-disable no-restricted-imports */
/* eslint-disable @typescript-eslint/naming-convention */
import { TwoFactorAuthService } from '../twofa/service';
import { ValidationError } from '../errors';

// Mock storage adapter
class MockStorageAdapter {
  private devices: Map<string, Record<string, unknown>> = new Map();
  private backupCodes: Map<string, Array<Record<string, unknown>>> = new Map();
  private sessions: Map<string, Record<string, unknown>> = new Map();

  async createTwoFactorDevice(data: unknown): Promise<unknown> {
    this.devices.set(data.id, data);
    return data;
  }

  async getTwoFactorDevice(deviceId: string): Promise<unknown> {
    return this.devices.get(deviceId) || null;
  }

  async updateTwoFactorDevice(deviceId: string, updates: unknown): Promise<unknown> {
    const device = this.devices.get(deviceId);
    if (!device) {
      return null;
    }
    const updated = { ...device, ...(updates as Record<string, unknown>) };
    this.devices.set(deviceId, updated);
    return updated;
  }

  async listTwoFactorDevices(userId: string): Promise<unknown[]> {
    return Array.from(this.devices.values()).filter(
      (d) => (d as { userId: string }).userId === userId
    );
  }

  async deleteTwoFactorDevice(deviceId: string): Promise<void> {
    this.devices.delete(deviceId);
  }

  async createBackupCodes(userId: string, codes: unknown[]): Promise<unknown[]> {
    this.backupCodes.set(userId, codes as Array<Record<string, unknown>>);
    return codes;
  }

  async getBackupCodes(userId: string): Promise<unknown[]> {
    return this.backupCodes.get(userId) || [];
  }

  async markBackupCodeUsed(codeId: string): Promise<void> {
    for (const codes of this.backupCodes.values()) {
      const code = codes.find((c) => (c as { id: string }).id === codeId);
      if (code) {
        (code as { used: boolean; usedAt: Date }).used = true;
        (code as { used: boolean; usedAt: Date }).usedAt = new Date();
      }
    }
  }

  async createTwoFactorSession(data: unknown): Promise<unknown> {
    const dataRecord = data as { id: string };
    this.sessions.set(dataRecord.id, data as Record<string, unknown>);
    return data;
  }

  async getTwoFactorSession(sessionId: string): Promise<unknown> {
    return this.sessions.get(sessionId) || null;
  }

  async completeTwoFactorSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      (session as { completedAt: Date }).completedAt = new Date();
    }
  }
}

describe('TwoFactorAuthService', () => {
  let twoFAService: TwoFactorAuthService;
  let mockStorage: MockStorageAdapter;

  beforeEach(() => {
    mockStorage = new MockStorageAdapter();
    twoFAService = new TwoFactorAuthService(
      mockStorage as unknown as import('../types').StorageAdapter,
      {
        enabled: true,
        methods: ['totp', 'sms'],
        backup_codes_count: 10,
        totp: {
          issuer: 'Test App',
        },
      }
    );
  });

  describe('TOTP Device Enrollment', () => {
    it('should enroll TOTP device', async () => {
      const device = await twoFAService.enrollTOTPDevice('user_1', 'My Phone');

      expect(device).toBeDefined();
      expect(device.method).toBe('totp');
      expect(device.verified).toBe(false);
      expect(device.name).toBe('My Phone');
      expect(device.qrCode).toBeDefined();
    });

    it('should throw error if TOTP method is disabled', async () => {
      const disabledService = new TwoFactorAuthService(
        mockStorage as unknown as import('../types').StorageAdapter,
        {
          enabled: true,
          methods: ['sms'], // TOTP not enabled
        }
      );

      await expect(disabledService.enrollTOTPDevice('user_1')).rejects.toThrow(ValidationError);
    });

    it('should throw error when 2FA is disabled', async () => {
      const disabledService = new TwoFactorAuthService(
        mockStorage as unknown as import('../types').StorageAdapter,
        {
          enabled: false,
          methods: [],
        }
      );

      await expect(disabledService.enrollTOTPDevice('user_1')).rejects.toThrow(ValidationError);
    });
  });

  describe('SMS Device Enrollment', () => {
    it('should enroll SMS device', async () => {
      const device = await twoFAService.enrollSMSDevice('user_1', '+1234567890', 'My Phone');

      expect(device).toBeDefined();
      expect(device.method).toBe('sms');
      expect(device.verified).toBe(false);
      expect(device.phoneNumber).toBe('+1234567890');
    });

    it('should throw error if phone number is missing', async () => {
      await expect(twoFAService.enrollSMSDevice('user_1', '', 'My Phone')).rejects.toThrow();
    });
  });

  describe('Device Management', () => {
    it('should get a device', async () => {
      const device = await twoFAService.enrollTOTPDevice('user_1');
      const retrieved = await twoFAService.getDevice(device.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe(device.id);
    });

    it('should list user devices', async () => {
      await twoFAService.enrollTOTPDevice('user_1');
      await twoFAService.enrollSMSDevice('user_1', '+1234567890');

      const devices = await twoFAService.listDevices('user_1');

      expect(devices).toHaveLength(2);
      expect(devices.some((d) => d.method === 'totp')).toBe(true);
      expect(devices.some((d) => d.method === 'sms')).toBe(true);
    });

    it('should delete a device', async () => {
      const device = await twoFAService.enrollTOTPDevice('user_1');
      await twoFAService.deleteDevice(device.id);

      const retrieved = await twoFAService.getDevice(device.id);
      expect(retrieved).toBeNull();
    });
  });

  describe('2FA Status', () => {
    it('should report disabled 2FA when no devices', async () => {
      const status = await twoFAService.getTwoFactorStatus('user_1');

      expect(status.enabled).toBe(false);
      expect(status.devices).toHaveLength(0);
      expect(status.backupCodesCount).toBe(0);
    });

    it('should report enabled 2FA when devices exist', async () => {
      await twoFAService.enrollTOTPDevice('user_1');

      const status = await twoFAService.getTwoFactorStatus('user_1');

      expect(status.enabled).toBe(true);
      expect(status.devices).toHaveLength(1);
      expect(status.enrolledAt).toBeDefined();
    });
  });

  describe('2FA Sessions', () => {
    it('should create 2FA session', async () => {
      const device = await twoFAService.enrollTOTPDevice('user_1');
      const session = await twoFAService.createTwoFactorSession('user_1', 'session_1', device.id);

      expect(session).toBeDefined();
      expect(session.userId).toBe('user_1');
      expect(session.deviceId).toBe(device.id);
      expect(session.method).toBe('totp');
    });

    it('should complete 2FA session', async () => {
      const device = await twoFAService.enrollTOTPDevice('user_1');
      const session = await twoFAService.createTwoFactorSession('user_1', 'session_1', device.id);

      await twoFAService.completeTwoFactorSession(session.id);

      const retrieved = await twoFAService.getTwoFactorSession?.(session.id);
      expect(retrieved?.completedAt).toBeDefined();
    });
  });

  describe('Disable 2FA', () => {
    it('should disable 2FA and remove all devices', async () => {
      await twoFAService.enrollTOTPDevice('user_1');
      await twoFAService.enrollSMSDevice('user_1', '+1234567890');

      let devices = await twoFAService.listDevices('user_1');
      expect(devices).toHaveLength(2);

      await twoFAService.disableTwoFactor('user_1');

      devices = await twoFAService.listDevices('user_1');
      expect(devices).toHaveLength(0);
    });
  });

  describe('2FA Disabled', () => {
    it('should throw error when 2FA is disabled', async () => {
      const disabledService = new TwoFactorAuthService(
        mockStorage as unknown as import('../types').StorageAdapter,
        {
          enabled: false,
          methods: [],
        }
      );

      await expect(disabledService.enableTwoFactor('user_1')).rejects.toThrow(ValidationError);
    });
  });
});
