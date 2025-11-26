// Core types for the authentication system

export type Scope = string;

export interface Principal {
  id: string;
  type: 'user' | 'org' | 'service';
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  metadata?: Record<string, any>;
}

export interface IssueApiKeyInput {
  principalId: string;
  scopes: Scope[];
  metadata?: Record<string, string>;
  expiresAt?: Date;
  name?: string;
  prefix?: string;
}

export interface IssueApiKeyResult {
  id: string;
  key: string;
  prefix: string;
  lastFour: string;
  expiresAt?: Date;
  createdAt: Date;
}

export interface VerifyApiKeyResult {
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
}

export interface Session {
  id: string;
  userId: string;
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  expiresAt: Date;
  createdAt: Date;
  metadata?: Record<string, any>;
}

export interface Entitlement {
  scope: Scope;
  plan: string;
  description?: string;
}

export interface Plan {
  id: string;
  name: string;
  entitlements: Scope[];
  seats?: number;
  metadata?: Record<string, any>;
}

export interface Organization {
  id: string;
  name: string;
  plan: string;
  seats: number;
  members: OrganizationMember[];
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganizationMember {
  userId: string;
  role: 'owner' | 'admin' | 'member';
  joinedAt: Date;
}

export interface AuthEvent {
  type: string;
  principalId: string;
  orgId?: string;
  data: Record<string, any>;
  timestamp: Date;
}

export interface RateLimit {
  limit: number;
  periodSec: number;
  remaining?: number;
  resetAt?: Date;
}

export interface AuthConfig {
  appUrl: string;
  providers: AuthProvider[];
  storage: StorageConfig;
  billing?: BillingConfig;
  apiKeys: ApiKeyConfig;
  sessions: SessionConfig;
  orgs?: OrganizationConfig;
  events?: EventConfig;
}

export interface AuthProvider {
  id: string;
  type: 'oauth' | 'email' | 'saml';
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes?: string[];
  metadata?: Record<string, any>;
}

export interface StorageConfig {
  driver: 'postgres' | 'mysql' | 'sqlite' | 'memory';
  url?: string;
  options?: Record<string, any>;
}

export interface BillingConfig {
  driver: 'stripe' | 'paddle' | 'custom';
  secretKey?: string;
  webhookSecret?: string;
  products: Record<string, BillingProduct>;
}

export interface BillingProduct {
  plan: string;
  entitlements: Scope[];
  seats?: number;
  metadata?: Record<string, any>;
}

export interface ApiKeyConfig {
  prefix: string;
  hash: {
    algo: 'argon2id' | 'bcrypt' | 'scrypt';
    timeCost?: number;
    memory?: number;
    parallelism?: number;
  };
  defaultExpiry?: number; // seconds
}

export interface SessionConfig {
  cookieName: string;
  ttlSeconds: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
}

export interface OrganizationConfig {
  enabled: boolean;
  defaultRole: 'owner' | 'admin' | 'member';
  maxSeats?: number;
}

export interface EventConfig {
  webhookSecret?: string;
  webhookUrl?: string;
  events: string[];
}

// Adapter interfaces
export interface StorageAdapter {
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
  storeTenantSAMLConfig?(config: any): Promise<void>;
  getTenantSAMLConfig?(tenantId: string): Promise<any | null>;
  updateTenantSAMLConfig?(tenantId: string, updates: Partial<any>): Promise<void>;
  deleteTenantSAMLConfig?(tenantId: string): Promise<void>;

  // RBAC (optional)
  createRole?(data: Omit<any, 'id' | 'createdAt' | 'updatedAt'>): Promise<any>;
  getRole?(roleId: string): Promise<any | null>;
  updateRole?(roleId: string, data: Partial<any>): Promise<any>;
  deleteRole?(roleId: string): Promise<void>;
  listRoles?(orgId: string): Promise<any[]>;
  assignRoleToUser?(userId: string, roleId: string, orgId: string): Promise<any>;
  revokeRoleFromUser?(userId: string, roleId: string, orgId: string): Promise<void>;
  getUserRoles?(userId: string, orgId: string): Promise<any[]>;

  // 2FA (optional)
  createTwoFactorDevice?(data: any): Promise<any>;
  getTwoFactorDevice?(deviceId: string): Promise<any | null>;
  updateTwoFactorDevice?(deviceId: string, data: Partial<any>): Promise<any>;
  listTwoFactorDevices?(userId: string): Promise<any[]>;
  deleteTwoFactorDevice?(deviceId: string): Promise<void>;
  createBackupCodes?(userId: string, codes: any[]): Promise<any[]>;
  getBackupCodes?(userId: string): Promise<any[]>;
  markBackupCodeUsed?(codeId: string): Promise<void>;
  createTwoFactorSession?(data: any): Promise<any>;
  getTwoFactorSession?(sessionId: string): Promise<any | null>;
  completeTwoFactorSession?(sessionId: string): Promise<void>;

  // SSO (optional)
  createSSOProvider?(data: any): Promise<any>;
  getSSOProvider?(providerId: string): Promise<any | null>;
  updateSSOProvider?(providerId: string, data: Partial<any>): Promise<any>;
  deleteSSOProvider?(providerId: string): Promise<void>;
  listSSOProviders?(orgId?: string): Promise<any[]>;
  createSSOLink?(data: any): Promise<any>;
  getSSOLink?(linkId: string): Promise<any | null>;
  getUserSSOLinks?(userId: string): Promise<any[]>;
  deleteSSOLink?(linkId: string): Promise<void>;
  createSSOSession?(data: any): Promise<any>;
  getSSOSession?(sessionId: string): Promise<any | null>;

  // Events
  emitEvent(event: AuthEvent): Promise<void>;
}

export interface BillingAdapter {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  createCustomer(data: CustomerData): Promise<Customer>;
  getCustomer(id: string): Promise<Customer | null>;
  updateCustomer(id: string, data: Partial<CustomerData>): Promise<Customer>;
  createSubscription(data: SubscriptionData): Promise<Subscription>;
  getSubscription(id: string): Promise<Subscription | null>;
  updateSubscription(id: string, data: Partial<SubscriptionData>): Promise<Subscription>;
  cancelSubscription(id: string): Promise<Subscription>;
  processWebhook(payload: any, signature: string): Promise<WebhookEvent>;
}

export interface CacheAdapter {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  get(key: string): Promise<any>;
  set(key: string, value: any, ttl?: number): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  expire(key: string, ttl: number): Promise<void>;
}

// Database record types
export interface ApiKeyRecord {
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
}

export interface SessionRecord {
  id: string;
  userId: string;
  orgId?: string;
  plan?: string;
  entitlements: Scope[];
  expiresAt: Date;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface OrganizationRecord {
  id: string;
  name: string;
  plan: string;
  seats: number;
  members: OrganizationMember[];
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

// User types
export interface User {
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements: Scope[];
  oauth?: Record<string, OAuthLink>;
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface OAuthLink {
  provider: string;
  sub: string;
  email?: string;
  name?: string;
  linkedAt: Date;
}

export interface UserRecord extends User {}

export interface CreateUserInput {
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements?: Scope[];
  metadata?: Record<string, any>;
}

export interface UpdateUserInput {
  email?: string;
  name?: string;
  picture?: string;
  plan?: string;
  entitlements?: Scope[];
  metadata?: Record<string, any>;
}

// Email verification types
export interface EmailVerificationToken {
  id: string;
  email: string;
  code: string;
  codeHash: string;
  type: 'verify_email' | 'reset_password' | 'change_email' | 'login_link';
  userId?: string;
  metadata?: Record<string, any>;
  expiresAt: Date;
  createdAt: Date;
  usedAt?: Date;
}

// Billing types
export interface Customer {
  id: string;
  email: string;
  name?: string;
  metadata?: Record<string, any>;
  createdAt: Date;
}

export interface CustomerData {
  email: string;
  name?: string;
  metadata?: Record<string, any>;
}

export interface Subscription {
  id: string;
  customerId: string;
  productId: string;
  status: 'active' | 'canceled' | 'past_due' | 'unpaid';
  currentPeriodStart: Date;
  currentPeriodEnd: Date;
  metadata?: Record<string, any>;
  createdAt: Date;
}

export interface SubscriptionData {
  customerId: string;
  productId: string;
  metadata?: Record<string, any>;
}

export interface WebhookEvent {
  type: string;
  data: any;
  timestamp: Date;
}

// OAuth types
export interface OAuthCallbackResult {
  userId: string;
  session: Session;
  profile: OAuthProfile;
  tokens: OAuthTokenResponse;
}

export interface OAuthProfile {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
  emailVerified?: boolean;
  metadata?: Record<string, any>;
}

export interface OAuthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn: number;
  tokenType: string;
  scope?: string;
}

export * from './provider';
export * from './rbac';
export * from './2fa';
export * from './sso';
