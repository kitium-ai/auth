/**
 * In-memory storage adapter
 * Development and testing adapter that stores data in memory
 */

import {
  StorageAdapter,
  ApiKeyRecord,
  SessionRecord,
  UserRecord,
  CreateUserInput,
  UpdateUserInput,
  OrganizationRecord,
  EmailVerificationToken,
  AuthEvent,
  OAuthLink,
} from '../types';

/**
 * In-memory storage adapter implementation
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private users = new Map<string, UserRecord>();
  private usersByEmail = new Map<string, UserRecord>();
  private usersByOAuth = new Map<string, UserRecord>();
  private sessions = new Map<string, SessionRecord>();
  private apiKeys = new Map<string, ApiKeyRecord>();
  private apiKeysByHash = new Map<string, ApiKeyRecord>();
  private organizations = new Map<string, OrganizationRecord>();
  private roles = new Map<string, any>();
  private twoFactorDevices = new Map<string, any>();
  private backupCodes = new Map<string, any[]>();
  private emailVerificationTokens = new Map<string, EmailVerificationToken>();
  private emailTokenAttempts = new Map<string, number>();
  private ssoProviders = new Map<string, any>();
  private ssoLinks = new Map<string, any>();
  private ssoSessions = new Map<string, any>();
  private tenantSAMLConfigs = new Map<string, any>();
  private userRoles = new Map<string, string[]>();
  private twoFactorSessions = new Map<string, any>();
  private events: AuthEvent[] = [];

  async connect(): Promise<void> {
    // No-op for memory adapter
  }

  async disconnect(): Promise<void> {
    // Clear all data on disconnect
    this.users.clear();
    this.usersByEmail.clear();
    this.usersByOAuth.clear();
    this.sessions.clear();
    this.apiKeys.clear();
    this.apiKeysByHash.clear();
    this.organizations.clear();
    this.roles.clear();
    this.twoFactorDevices.clear();
    this.backupCodes.clear();
    this.emailVerificationTokens.clear();
    this.emailTokenAttempts.clear();
    this.ssoProviders.clear();
    this.ssoLinks.clear();
    this.ssoSessions.clear();
    this.tenantSAMLConfigs.clear();
    this.userRoles.clear();
    this.twoFactorSessions.clear();
    this.events = [];
  }

  // ===== API Keys =====
  async createApiKey(data: Omit<ApiKeyRecord, 'id' | 'createdAt'>): Promise<ApiKeyRecord> {
    const record: ApiKeyRecord = {
      id: `key_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.apiKeys.set(record.id, record);
    this.apiKeysByHash.set(record.hash, record);
    return record;
  }

  async getApiKey(id: string): Promise<ApiKeyRecord | null> {
    return this.apiKeys.get(id) || null;
  }

  async getApiKeyByHash(hash: string): Promise<ApiKeyRecord | null> {
    return this.apiKeysByHash.get(hash) || null;
  }

  async getApiKeysByPrefixAndLastFour(prefix: string, lastFour: string): Promise<ApiKeyRecord[]> {
    return Array.from(this.apiKeys.values()).filter(
      (k) => k.prefix === prefix && k.lastFour === lastFour
    );
  }

  async updateApiKey(id: string, data: Partial<ApiKeyRecord>): Promise<ApiKeyRecord> {
    const key = this.apiKeys.get(id);
    if (!key) throw new Error(`API key ${id} not found`);

    const updated: ApiKeyRecord = {
      ...key,
      ...data,
      id: key.id,
      createdAt: key.createdAt,
      updatedAt: new Date(),
    };

    this.apiKeys.set(id, updated);
    if (data.hash) {
      this.apiKeysByHash.delete(key.hash);
      this.apiKeysByHash.set(data.hash, updated);
    }
    return updated;
  }

  async deleteApiKey(id: string): Promise<void> {
    const key = this.apiKeys.get(id);
    if (key) {
      this.apiKeys.delete(id);
      this.apiKeysByHash.delete(key.hash);
    }
  }

  async listApiKeys(principalId: string): Promise<ApiKeyRecord[]> {
    return Array.from(this.apiKeys.values()).filter((k) => k.principalId === principalId);
  }

  // ===== Sessions =====
  async createSession(data: Omit<SessionRecord, 'id' | 'createdAt'>): Promise<SessionRecord> {
    const record: SessionRecord = {
      id: `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.sessions.set(record.id, record);
    return record;
  }

  async getSession(id: string): Promise<SessionRecord | null> {
    const session = this.sessions.get(id);
    if (session && new Date() > session.expiresAt) {
      this.sessions.delete(id);
      return null;
    }
    return session || null;
  }

  async updateSession(id: string, data: Partial<SessionRecord>): Promise<SessionRecord> {
    const session = this.sessions.get(id);
    if (!session) throw new Error(`Session ${id} not found`);

    const updated: SessionRecord = {
      ...session,
      ...data,
      id: session.id,
      createdAt: session.createdAt,
      updatedAt: new Date(),
    };

    this.sessions.set(id, updated);
    return updated;
  }

  async deleteSession(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  // ===== Organizations =====
  async createOrganization(
    data: Omit<OrganizationRecord, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<OrganizationRecord> {
    const record: OrganizationRecord = {
      id: `org_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.organizations.set(record.id, record);
    return record;
  }

  async getOrganization(id: string): Promise<OrganizationRecord | null> {
    return this.organizations.get(id) || null;
  }

  async updateOrganization(
    id: string,
    data: Partial<OrganizationRecord>
  ): Promise<OrganizationRecord> {
    const org = this.organizations.get(id);
    if (!org) throw new Error(`Organization ${id} not found`);

    const updated: OrganizationRecord = {
      ...org,
      ...data,
      id: org.id,
      createdAt: org.createdAt,
      updatedAt: new Date(),
    };

    this.organizations.set(id, updated);
    return updated;
  }

  async deleteOrganization(id: string): Promise<void> {
    this.organizations.delete(id);
  }

  // ===== Users =====
  async createUser(data: CreateUserInput): Promise<UserRecord> {
    const record: UserRecord = {
      id: `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      entitlements: data.entitlements || [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.users.set(record.id, record);
    if (record.email) {
      this.usersByEmail.set(record.email.toLowerCase(), record);
    }
    return record;
  }

  async getUser(id: string): Promise<UserRecord | null> {
    return this.users.get(id) || null;
  }

  async getUserByEmail(email: string): Promise<UserRecord | null> {
    return this.usersByEmail.get(email.toLowerCase()) || null;
  }

  async getUserByOAuth(provider: string, sub: string): Promise<UserRecord | null> {
    const key = `${provider}:${sub}`;
    return this.usersByOAuth.get(key) || null;
  }

  async updateUser(id: string, data: UpdateUserInput): Promise<UserRecord> {
    const user = this.users.get(id);
    if (!user) throw new Error(`User ${id} not found`);

    const updated: UserRecord = {
      ...user,
      ...data,
      entitlements: data.entitlements || user.entitlements,
      id: user.id,
      createdAt: user.createdAt,
      updatedAt: new Date(),
    };

    this.users.set(id, updated);

    // Update email index
    if (data.email && data.email !== user.email) {
      if (user.email) {
        this.usersByEmail.delete(user.email.toLowerCase());
      }
      this.usersByEmail.set(data.email.toLowerCase(), updated);
    }

    return updated;
  }

  async deleteUser(id: string): Promise<void> {
    const user = this.users.get(id);
    if (user && user.email) {
      this.usersByEmail.delete(user.email.toLowerCase());
    }
    this.users.delete(id);

    // Clean up related data
    this.backupCodes.delete(id);
    this.userRoles.delete(id);
    Array.from(this.usersByOAuth.entries()).forEach(([key, u]) => {
      if (u.id === id) {
        this.usersByOAuth.delete(key);
      }
    });
  }

  async linkOAuthAccount(
    userId: string,
    provider: string,
    oauthLink: OAuthLink
  ): Promise<UserRecord> {
    const user = this.users.get(userId);
    if (!user) throw new Error(`User ${userId} not found`);

    if (!user.oauth) {
      user.oauth = {};
    }

    user.oauth[provider] = oauthLink;
    const key = `${provider}:${oauthLink.sub}`;
    this.usersByOAuth.set(key, user);

    return user;
  }

  // ===== Email Verification Tokens =====
  async createEmailVerificationToken(
    data: Omit<EmailVerificationToken, 'id'>
  ): Promise<EmailVerificationToken> {
    const record: EmailVerificationToken = {
      id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.emailVerificationTokens.set(record.id, record);
    this.emailTokenAttempts.set(record.id, 0);
    return record;
  }

  async getEmailVerificationTokens(
    email: string,
    type?: string
  ): Promise<EmailVerificationToken[]> {
    const tokens = Array.from(this.emailVerificationTokens.values()).filter(
      (t) => t.email.toLowerCase() === email.toLowerCase() && (!type || t.type === type)
    );

    return tokens.filter((t) => !t.usedAt && new Date() < t.expiresAt);
  }

  async getEmailVerificationTokenById(id: string): Promise<EmailVerificationToken | null> {
    const token = this.emailVerificationTokens.get(id);
    if (!token) return null;

    if (new Date() > token.expiresAt) {
      this.emailVerificationTokens.delete(id);
      return null;
    }

    return token;
  }

  async markEmailVerificationTokenAsUsed(id: string): Promise<EmailVerificationToken> {
    const token = this.emailVerificationTokens.get(id);
    if (!token) throw new Error(`Token ${id} not found`);

    token.usedAt = new Date();
    return token;
  }

  async deleteExpiredEmailVerificationTokens(): Promise<number> {
    const now = new Date();
    let count = 0;

    for (const [id, token] of this.emailVerificationTokens.entries()) {
      if (now > token.expiresAt) {
        this.emailVerificationTokens.delete(id);
        this.emailTokenAttempts.delete(id);
        count++;
      }
    }

    return count;
  }

  async getEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    return this.emailTokenAttempts.get(tokenId) || 0;
  }

  async incrementEmailVerificationTokenAttempts(tokenId: string): Promise<number> {
    const current = this.emailTokenAttempts.get(tokenId) || 0;
    const updated = current + 1;
    this.emailTokenAttempts.set(tokenId, updated);
    return updated;
  }

  // ===== SAML Configuration =====
  async storeTenantSAMLConfig(config: any): Promise<void> {
    this.tenantSAMLConfigs.set(config.tenantId, config);
  }

  async getTenantSAMLConfig(tenantId: string): Promise<any | null> {
    return this.tenantSAMLConfigs.get(tenantId) || null;
  }

  async updateTenantSAMLConfig(tenantId: string, updates: Partial<any>): Promise<void> {
    const config = this.tenantSAMLConfigs.get(tenantId);
    if (!config) throw new Error(`SAML config for tenant ${tenantId} not found`);
    this.tenantSAMLConfigs.set(tenantId, { ...config, ...updates });
  }

  async deleteTenantSAMLConfig(tenantId: string): Promise<void> {
    this.tenantSAMLConfigs.delete(tenantId);
  }

  // ===== RBAC =====
  async createRole(data: Omit<any, 'id' | 'createdAt' | 'updatedAt'>): Promise<any> {
    const role = {
      id: `role_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.roles.set(role.id, role);
    return role;
  }

  async getRole(roleId: string): Promise<any | null> {
    return this.roles.get(roleId) || null;
  }

  async updateRole(roleId: string, data: Partial<any>): Promise<any> {
    const role = this.roles.get(roleId);
    if (!role) throw new Error(`Role ${roleId} not found`);

    const updated = {
      ...role,
      ...data,
      id: role.id,
      createdAt: role.createdAt,
      updatedAt: new Date(),
    };
    this.roles.set(roleId, updated);
    return updated;
  }

  async deleteRole(roleId: string): Promise<void> {
    this.roles.delete(roleId);
  }

  async listRoles(orgId: string): Promise<any[]> {
    return Array.from(this.roles.values()).filter((r) => r.orgId === orgId);
  }

  async assignRoleToUser(userId: string, roleId: string, orgId: string): Promise<any> {
    const role = this.roles.get(roleId);
    if (!role) throw new Error(`Role ${roleId} not found`);

    const key = `${userId}:${orgId}`;
    const roles = this.userRoles.get(key) || [];
    if (!roles.includes(roleId)) {
      roles.push(roleId);
      this.userRoles.set(key, roles);
    }

    return role;
  }

  async revokeRoleFromUser(userId: string, roleId: string, orgId: string): Promise<void> {
    const key = `${userId}:${orgId}`;
    const roles = this.userRoles.get(key) || [];
    const index = roles.indexOf(roleId);
    if (index > -1) {
      roles.splice(index, 1);
      this.userRoles.set(key, roles);
    }
  }

  async getUserRoles(userId: string, orgId: string): Promise<any[]> {
    const key = `${userId}:${orgId}`;
    const roleIds = this.userRoles.get(key) || [];
    return roleIds.map((id) => this.roles.get(id)).filter((r) => r !== undefined);
  }

  // ===== 2FA =====
  async createTwoFactorDevice(data: any): Promise<any> {
    const device = {
      id: `2fa_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.twoFactorDevices.set(device.id, device);
    return device;
  }

  async getTwoFactorDevice(deviceId: string): Promise<any | null> {
    return this.twoFactorDevices.get(deviceId) || null;
  }

  async updateTwoFactorDevice(deviceId: string, data: Partial<any>): Promise<any> {
    const device = this.twoFactorDevices.get(deviceId);
    if (!device) throw new Error(`2FA device ${deviceId} not found`);

    const updated = { ...device, ...data, id: device.id, createdAt: device.createdAt };
    this.twoFactorDevices.set(deviceId, updated);
    return updated;
  }

  async listTwoFactorDevices(userId: string): Promise<any[]> {
    return Array.from(this.twoFactorDevices.values()).filter((d) => d.userId === userId);
  }

  async deleteTwoFactorDevice(deviceId: string): Promise<void> {
    this.twoFactorDevices.delete(deviceId);
  }

  async createBackupCodes(userId: string, codes: any[]): Promise<any[]> {
    this.backupCodes.set(userId, codes);
    return codes;
  }

  async getBackupCodes(userId: string): Promise<any[]> {
    return this.backupCodes.get(userId) || [];
  }

  async markBackupCodeUsed(codeId: string): Promise<void> {
    for (const codes of this.backupCodes.values()) {
      const code = codes.find((c) => c.id === codeId);
      if (code) {
        code.used = true;
      }
    }
  }

  async createTwoFactorSession(data: any): Promise<any> {
    const session = {
      id: `2fa_session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.twoFactorSessions.set(session.id, session);
    return session;
  }

  async getTwoFactorSession(sessionId: string): Promise<any | null> {
    return this.twoFactorSessions.get(sessionId) || null;
  }

  async completeTwoFactorSession(sessionId: string): Promise<void> {
    this.twoFactorSessions.delete(sessionId);
  }

  // ===== SSO =====
  async createSSOProvider(data: any): Promise<any> {
    const provider = {
      id: `sso_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.ssoProviders.set(provider.id, provider);
    return provider;
  }

  async getSSOProvider(providerId: string): Promise<any | null> {
    return this.ssoProviders.get(providerId) || null;
  }

  async updateSSOProvider(providerId: string, data: Partial<any>): Promise<any> {
    const provider = this.ssoProviders.get(providerId);
    if (!provider) throw new Error(`SSO provider ${providerId} not found`);

    const updated = { ...provider, ...data, id: provider.id, createdAt: provider.createdAt };
    this.ssoProviders.set(providerId, updated);
    return updated;
  }

  async deleteSSOProvider(providerId: string): Promise<void> {
    this.ssoProviders.delete(providerId);
  }

  async listSSOProviders(orgId?: string): Promise<any[]> {
    const providers = Array.from(this.ssoProviders.values());
    return orgId ? providers.filter((p) => p.orgId === orgId) : providers;
  }

  async createSSOLink(data: any): Promise<any> {
    const link = {
      id: `sso_link_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.ssoLinks.set(link.id, link);
    return link;
  }

  async getSSOLink(linkId: string): Promise<any | null> {
    return this.ssoLinks.get(linkId) || null;
  }

  async getUserSSOLinks(userId: string): Promise<any[]> {
    return Array.from(this.ssoLinks.values()).filter((l) => l.userId === userId);
  }

  async deleteSSOLink(linkId: string): Promise<void> {
    this.ssoLinks.delete(linkId);
  }

  async createSSOSession(data: any): Promise<any> {
    const session = {
      id: `sso_session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...data,
      createdAt: new Date(),
    };

    this.ssoSessions.set(session.id, session);
    return session;
  }

  async getSSOSession(sessionId: string): Promise<any | null> {
    return this.ssoSessions.get(sessionId) || null;
  }

  // ===== Events =====
  async emitEvent(event: AuthEvent): Promise<void> {
    this.events.push(event);
  }

  // ===== Helper Methods =====
  /**
   * Get all events (useful for testing)
   */
  getEvents(): AuthEvent[] {
    return [...this.events];
  }

  /**
   * Clear all events (useful for testing)
   */
  clearEvents(): void {
    this.events = [];
  }

  /**
   * Get event count by type (useful for testing)
   */
  getEventCount(type: string): number {
    return this.events.filter((e) => e.type === type).length;
  }
}
