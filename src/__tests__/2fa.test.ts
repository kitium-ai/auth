import { TwoFactorAuthService } from '../twofa/service';
import { ValidationError, AuthenticationError } from '../errors';

// Mock storage adapter
class MockStorageAdapter {
  private devices: Map<string, any> = new Map();
  private backupCodes: Map<string, any[]> = new Map();
  private sessions: Map<string, any> = new Map();

  async createTwoFactorDevice(data: any) {
    this.devices.set(data.id, data);
    return data;
  }

  async getTwoFactorDevice(deviceId: string) {
    return this.devices.get(deviceId) || null;
  }

  async updateTwoFactorDevice(deviceId: string, updates: any) {
    const device = this.devices.get(deviceId);
    if (!device) return null;
    const updated = { ...device, ...updates };
    this.devices.set(deviceId, updated);
    return updated;
  }

  async listTwoFactorDevices(userId: string) {
    return Array.from(this.devices.values()).filter((d) => d.userId === userId);
  }

  async deleteTwoFactorDevice(deviceId: string) {
    this.devices.delete(deviceId);
  }

  async createBackupCodes(userId: string, codes: any[]) {
    this.backupCodes.set(userId, codes);
    return codes;
  }

  async getBackupCodes(userId: string) {
    return this.backupCodes.get(userId) || [];
  }

  async markBackupCodeUsed(codeId: string) {
    for (const codes of this.backupCodes.values()) {
      const code = codes.find((c) => c.id === codeId);
      if (code) {
        code.used = true;
        code.usedAt = new Date();
      }
    }
  }

  async createTwoFactorSession(data: any) {
    this.sessions.set(data.id, data);
    return data;
  }

  async getTwoFactorSession(sessionId: string) {
    return this.sessions.get(sessionId) || null;
  }

  async completeTwoFactorSession(sessionId: string) {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.completedAt = new Date();
    }
  }
}

describe('TwoFactorAuthService', () => {
  let twoFAService: TwoFactorAuthService;
  let mockStorage: MockStorageAdapter;

  beforeEach(() => {
    mockStorage = new MockStorageAdapter();
    twoFAService = new TwoFactorAuthService(mockStorage as any, {
      enabled: true,
      methods: ['totp', 'sms'],
      backup_codes_count: 10,
      totp: {
        issuer: 'Test App',
      },
    });
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
      const disabledService = new TwoFactorAuthService(mockStorage as any, {
        enabled: true,
        methods: ['sms'], // TOTP not enabled
      });

      await expect(disabledService.enrollTOTPDevice('user_1')).rejects.toThrow(ValidationError);
    });

    it('should throw error when 2FA is disabled', async () => {
      const disabledService = new TwoFactorAuthService(mockStorage as any, {
        enabled: false,
        methods: [],
      });

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
      const disabledService = new TwoFactorAuthService(mockStorage as any, {
        enabled: false,
        methods: [],
      });

      await expect(disabledService.enableTwoFactor('user_1')).rejects.toThrow(ValidationError);
    });
  });
});
