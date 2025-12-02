// Two-Factor Authentication (2FA) types

export type TwoFactorMethod = 'totp' | 'sms' | 'backup-code';

export type TwoFactorConfig = {
  enabled: boolean;
  required?: boolean; // Mandatory 2FA for all users
  methods: TwoFactorMethod[];
  grace_period_days?: number; // Days to enable 2FA after first login
  backup_codes_count?: number; // Number of backup codes to generate
  sms?: {
    provider: 'twilio' | 'aws-sns' | 'custom';
    apiKey?: string;
    apiSecret?: string;
    from?: string;
  };
  totp?: {
    issuer: string;
    algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
    digits?: number; // 6 or 8 digit codes
    period?: number; // Time period in seconds (default 30)
  };
};

export type TwoFactorDevice = {
  id: string;
  userId: string;
  method: TwoFactorMethod;
  name?: string;
  verified: boolean;
  phoneNumber?: string;
  secret?: string;
  lastUsedAt?: Date;
  createdAt: Date;
  updatedAt?: Date;
  metadata?: Record<string, unknown>;
};

export type TOTPDevice = {
  method: 'totp';
  secret: string; // Encrypted secret for authenticator apps
  backupCodesUsed: string[]; // Used backup code IDs
} & TwoFactorDevice;

export type SMSDevice = {
  method: 'sms';
  phoneNumber: string;
  verificationCode?: string;
  verificationCodeExpiresAt?: Date;
} & TwoFactorDevice;

export type BackupCode = {
  id: string;
  userId: string;
  code: string; // Hashed code
  used: boolean;
  usedAt?: Date;
  createdAt: Date;
};

export type TwoFactorSession = {
  id: string;
  userId: string;
  sessionId: string;
  deviceId: string;
  method: TwoFactorMethod;
  verificationCode?: string;
  attemptCount: number;
  maxAttempts: number;
  expiresAt: Date;
  createdAt: Date;
  completedAt?: Date;
};

export type TwoFactorChallenge = {
  challengeId: string;
  userId: string;
  method: TwoFactorMethod;
  deviceId: string;
  expiresAt: Date;
  verificationCode?: string;
  attemptCount: number;
  maxAttempts: number;
};

export type EnrollTwoFactorInput = {
  userId: string;
  method: TwoFactorMethod;
  phoneNumber?: string; // For SMS
  name?: string; // Device name
};

export type VerifyTwoFactorInput = {
  userId: string;
  deviceId: string;
  code: string;
  sessionId?: string;
  rememberDevice?: boolean; // Remember device for 30 days
};

export type TwoFactorStatus = {
  userId: string;
  enabled: boolean;
  enrolledAt?: Date;
  devices: TwoFactorDevice[];
  backupCodesCount: number;
  backupCodesUsedCount: number;
};

// Database record types
export type TOTPDeviceRecord = TOTPDevice;

export type SMSDeviceRecord = SMSDevice;

export type BackupCodeRecord = BackupCode;

export type TwoFactorSessionRecord = TwoFactorSession;
