// Core types for the authentication system

import type { BackupCode, TwoFactorDevice, TwoFactorSession } from './2fa';
import type { RoleRecord } from './rbac';
import type { SSOLink, SSOSession } from './sso';

export type Scope = string;

export type Principal = {
  id: string;
  type: 'user' | 'org' | 'service';
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  metadata?: Record<string, unknown>;
};

export type IssueApiKeyInput = {
  principalId: string;
  scopes: Scope[];
  metadata?: Record<string, string>;
  expiresAt?: Date;
  name?: string;
  prefix?: string;
};

export type IssueApiKeyResult = {
  id: string;
  key: string;
  prefix: string;
  lastFour: string;
  expiresAt?: Date;
  createdAt: Date;
};

export type VerifyApiKeyResult = {
  valid: boolean;
  principalId?: string;
  scopes?: Scope[];
  plan?: string;
  orgId?: string;
  rateLimit?: {
    limit: number;
    periodSec: number;
  };
  keyId?: string;
  expiresAt?: Date;
};

export type Session = {
  id: string;
  userId: string;
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  expiresAt: Date;
  createdAt: Date;
  metadata?: Record<string, unknown>;
};

export type Entitlement = {
  scope: Scope;
  plan: string;
  description?: string;
};

export type Plan = {
  id: string;
  name: string;
  entitlements: Scope[];
  seats?: number;
  metadata?: Record<string, unknown>;
};

export type Organization = {
  id: string;
  name: string;
  plan: string;
  seats: number;
  members: OrganizationMember[];
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

export type OrganizationMember = {
  userId: string;
  role: 'owner' | 'admin' | 'member';
  joinedAt: Date;
};

export type AuthEvent = {
  type: string;
  principalId: string;
  orgId?: string;
  data: Record<string, unknown>;
  timestamp: Date;
};

export type RateLimit = {
  limit: number;
  periodSec: number;
  remaining?: number;
  resetAt?: Date;
};

export type AuthConfig = {
  appUrl: string;
  providers: AuthProvider[];
  storage: StorageConfig;
  billing?: BillingConfig;
  apiKeys: ApiKeyConfig;
  sessions: SessionConfig;
  orgs?: OrganizationConfig;
  events?: EventConfig;
};

export type AuthProvider = {
  id: string;
  type: 'oauth' | 'email' | 'saml';
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes?: string[];
  metadata?: Record<string, unknown>;
};

export type StorageConfig = {
  driver: 'postgres' | 'mysql' | 'sqlite' | 'memory';
  url?: string;
  options?: Record<string, unknown>;
};

export type BillingConfig = {
  driver: 'stripe' | 'paddle' | 'custom';
  secretKey?: string;
  webhookSecret?: string;
  products: Record<string, BillingProduct>;
};

export type BillingProduct = {
  plan: string;
  entitlements: Scope[];
  seats?: number;
  metadata?: Record<string, unknown>;
};

export type ApiKeyConfig = {
  prefix: string;
  hash: {
    algo: 'argon2id' | 'bcrypt' | 'scrypt';
    timeCost?: number;
    memory?: number;
    parallelism?: number;
  };
  defaultExpiry?: number; // seconds
};

export type SessionConfig = {
  cookieName: string;
  ttlSeconds: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
};

export type OrganizationConfig = {
  enabled: boolean;
  defaultRole: 'owner' | 'admin' | 'member';
  maxSeats?: number;
};

export type EventConfig = {
  webhookSecret?: string;
  webhookUrl?: string;
  events: string[];
};

// Adapter interfaces
export type StorageAdapter = {
  connect(): Promise<void>;
  disconnect(): Promise<void>;

  // API Keys
  createApiKey(data: Omit<ApiKeyRecord, 'id' | 'createdAt'>): Promise<ApiKeyRecord>;
  getApiKey(id: string): Promise<ApiKeyRecord | null>;
  getApiKeyByHash(hash: string): Promise<ApiKeyRecord | null>;
  getApiKeysByPrefixAndLastFour(prefix: string, lastFour: string): Promise<ApiKeyRecord[]>;
  updateApiKey(id: string, data: Partial<ApiKeyRecord>): Promise<ApiKeyRecord>;
  deleteApiKey(id: string): Promise<void>;
  listApiKeys(principalId: string): Promise<ApiKeyRecord[]>;

  // Sessions
  createSession(data: Omit<SessionRecord, 'id' | 'createdAt'>): Promise<SessionRecord>;
  getSession(id: string): Promise<SessionRecord | null>;
  updateSession(id: string, data: Partial<SessionRecord>): Promise<SessionRecord>;
  deleteSession(id: string): Promise<void>;

  // Organizations
  createOrganization(
    data: Omit<OrganizationRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<OrganizationRecord>;
  getOrganization(id: string): Promise<OrganizationRecord | null>;
  updateOrganization(id: string, data: Partial<OrganizationRecord>): Promise<OrganizationRecord>;
  deleteOrganization(id: string): Promise<void>;

  // Users
  createUser(data: CreateUserInput): Promise<UserRecord>;
  getUser(id: string): Promise<UserRecord | null>;
  getUserByEmail(email: string): Promise<UserRecord | null>;
  getUserByOAuth(provider: string, sub: string): Promise<UserRecord | null>;
  updateUser(id: string, data: UpdateUserInput): Promise<UserRecord>;
  deleteUser(id: string): Promise<void>;
  linkOAuthAccount(userId: string, provider: string, oauthLink: OAuthLink): Promise<UserRecord>;

  // Email Verification Tokens
  createEmailVerificationToken(
    data: Omit<EmailVerificationToken, 'id'>
  ): Promise<EmailVerificationToken>;
  getEmailVerificationTokens(email: string, type?: string): Promise<EmailVerificationToken[]>;
  getEmailVerificationTokenById(id: string): Promise<EmailVerificationToken | null>;
  markEmailVerificationTokenAsUsed(id: string): Promise<EmailVerificationToken>;
  deleteExpiredEmailVerificationTokens(): Promise<number>;
  getEmailVerificationTokenAttempts(tokenId: string): Promise<number>;
  incrementEmailVerificationTokenAttempts(tokenId: string): Promise<number>;

  // SAML Configuration (optional - for multi-tenant SAML)
  storeTenantSAMLConfig?(config: unknown): Promise<void>;
  getTenantSAMLConfig?(tenantId: string): Promise<unknown | null>;
  updateTenantSAMLConfig?(tenantId: string, updates: Partial<unknown>): Promise<void>;
  deleteTenantSAMLConfig?(tenantId: string): Promise<void>;

  // RBAC (optional)
  createRole?(data: Omit<RoleRecord, 'id' | 'createdAt' | 'updatedAt'>): Promise<RoleRecord>;
  getRole?(roleId: string): Promise<RoleRecord | null>;
  updateRole?(roleId: string, data: Partial<RoleRecord>): Promise<RoleRecord>;
  deleteRole?(roleId: string): Promise<void>;
  listRoles?(orgId: string): Promise<RoleRecord[]>;
  assignRoleToUser?(userId: string, roleId: string, orgId: string): Promise<RoleRecord>;
  revokeRoleFromUser?(userId: string, roleId: string, orgId: string): Promise<void>;
  getUserRoles?(userId: string, orgId: string): Promise<RoleRecord[]>;

  // 2FA (optional)
  createTwoFactorDevice?(data: Omit<TwoFactorDevice, 'id' | 'createdAt'>): Promise<TwoFactorDevice>;
  getTwoFactorDevice?(deviceId: string): Promise<TwoFactorDevice | null>;
  updateTwoFactorDevice?(
    deviceId: string,
    data: Partial<TwoFactorDevice>
  ): Promise<TwoFactorDevice>;
  listTwoFactorDevices?(userId: string): Promise<TwoFactorDevice[]>;
  deleteTwoFactorDevice?(deviceId: string): Promise<void>;
  createBackupCodes?(userId: string, codes: BackupCode[]): Promise<BackupCode[]>;
  getBackupCodes?(userId: string): Promise<BackupCode[]>;
  markBackupCodeUsed?(codeId: string): Promise<void>;
  createTwoFactorSession?(data: TwoFactorSession): Promise<TwoFactorSession>;
  getTwoFactorSession?(sessionId: string): Promise<TwoFactorSession | null>;
  completeTwoFactorSession?(sessionId: string): Promise<void>;

  // SSO (optional)
  createSSOProvider?(data: unknown): Promise<unknown>;
  getSSOProvider?(providerId: string): Promise<unknown | null>;
  updateSSOProvider?(providerId: string, data: Partial<unknown>): Promise<unknown>;
  deleteSSOProvider?(providerId: string): Promise<void>;
  listSSOProviders?(orgId?: string): Promise<unknown[]>;
  createSSOLink?(data: Omit<SSOLink, 'id' | 'linkedAt'>): Promise<SSOLink>;
  getSSOLink?(linkId: string): Promise<SSOLink | null>;
  getUserSSOLinks?(userId: string): Promise<SSOLink[]>;
  deleteSSOLink?(linkId: string): Promise<void>;
  createSSOSession?(data: Omit<SSOSession, 'id' | 'linkedAt'>): Promise<SSOSession>;
  getSSOSession?(sessionId: string): Promise<SSOSession | null>;

  // Events
  emitEvent(event: AuthEvent): Promise<void>;
};

export type BillingAdapter = {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  createCustomer(data: CustomerData): Promise<Customer>;
  getCustomer(id: string): Promise<Customer | null>;
  updateCustomer(id: string, data: Partial<CustomerData>): Promise<Customer>;
  createSubscription(data: SubscriptionData): Promise<Subscription>;
  getSubscription(id: string): Promise<Subscription | null>;
  updateSubscription(id: string, data: Partial<SubscriptionData>): Promise<Subscription>;
  cancelSubscription(id: string): Promise<Subscription>;
  processWebhook(payload: unknown, signature: string): Promise<WebhookEvent>;
};

export type CacheAdapter = {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  expire(key: string, ttl: number): Promise<void>;
};

// Database record types
export type ApiKeyRecord = {
  id: string;
  principalId: string;
  hash: string;
  prefix: string;
  lastFour: string;
  scopes: Scope[];
  metadata?: Record<string, string>;
  expiresAt?: Date;
  createdAt: Date;
  updatedAt: Date;
};

export type SessionRecord = {
  id: string;
  userId: string;
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  expiresAt: Date;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

export type OrganizationRecord = {
  id: string;
  name: string;
  plan: string;
  seats: number;
  members: OrganizationMember[];
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

// User types
export type User = {
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements: Scope[];
  oauth?: Record<string, OAuthLink>;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

export type OAuthLink = {
  provider: string;
  sub: string;
  email?: string;
  name?: string;
  linkedAt: Date;
};

export type UserRecord = User;

export type CreateUserInput = {
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements?: Scope[];
  metadata?: Record<string, unknown>;
};

export type UpdateUserInput = {
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements?: Scope[];
  metadata?: Record<string, unknown>;
};

// Email verification types
export type EmailVerificationToken = {
  id: string;
  email: string;
  code: string;
  codeHash: string;
  type: 'verify_email' | 'reset_password' | 'change_email' | 'login_link';
  userId?: string;
  metadata?: Record<string, unknown>;
  expiresAt: Date;
  createdAt: Date;
  usedAt?: Date;
};

// Billing types
export type Customer = {
  id: string;
  email: string;
  name?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
};

export type CustomerData = {
  email: string;
  name?: string;
  metadata?: Record<string, unknown>;
};

export type Subscription = {
  id: string;
  customerId: string;
  productId: string;
  status: 'active' | 'canceled' | 'past_due' | 'unpaid';
  currentPeriodStart: Date;
  currentPeriodEnd: Date;
  metadata?: Record<string, unknown>;
  createdAt: Date;
};

export type SubscriptionData = {
  customerId: string;
  productId: string;
  metadata?: Record<string, unknown>;
};

export type WebhookEvent = {
  type: string;
  data: Record<string, unknown>;
  timestamp: Date;
};

// OAuth types
export type OAuthCallbackResult = {
  userId: string;
  session: Session;
  profile: OAuthProfile;
  tokens: OAuthTokenResponse;
};

export type OAuthProfile = {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
  emailVerified?: boolean;
  metadata?: Record<string, unknown>;
};

export type OAuthTokenResponse = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn: number;
  tokenType: string;
  scope?: string;
};

export * from './2fa';
export * from './provider';
export * from './rbac';
export * from './sso';
