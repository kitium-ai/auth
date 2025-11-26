/* eslint-disable no-restricted-imports */
/* eslint-disable @typescript-eslint/naming-convention */
import { SSOService } from '../sso/service';
import { ValidationError } from '../errors';

// Mock storage adapter
class MockStorageAdapter {
  private providers: Map<string, Record<string, unknown>> = new Map();
  private ssoLinks: Map<string, Record<string, unknown>> = new Map();
  private ssoSessions: Map<string, Record<string, unknown>> = new Map();

  async createSSOProvider(data: unknown): Promise<unknown> {
    const dataRecord = data as { id: string };
    this.providers.set(dataRecord.id, data as Record<string, unknown>);
    return data;
  }

  async getSSOProvider(providerId: string): Promise<unknown> {
    return this.providers.get(providerId) || null;
  }

  async updateSSOProvider(providerId: string, updates: unknown): Promise<unknown> {
    const provider = this.providers.get(providerId);
    if (!provider) {
      return null;
    }
    const updated = { ...provider, ...(updates as Record<string, unknown>) };
    this.providers.set(providerId, updated);
    return updated;
  }

  async deleteSSOProvider(providerId: string): Promise<void> {
    this.providers.delete(providerId);
  }

  async listSSOProviders(orgId?: string): Promise<unknown[]> {
    return Array.from(this.providers.values()).filter(
      (p) => !orgId || (p as { orgId?: string }).orgId === orgId
    );
  }

  async createSSOLink(data: unknown): Promise<unknown> {
    const dataRecord = data as { id: string };
    this.ssoLinks.set(dataRecord.id, data as Record<string, unknown>);
    return data;
  }

  async getSSOLink(linkId: string): Promise<unknown> {
    return this.ssoLinks.get(linkId) || null;
  }

  async getUserSSOLinks(userId: string): Promise<unknown[]> {
    return Array.from(this.ssoLinks.values()).filter(
      (l) => (l as { userId: string }).userId === userId
    );
  }

  async deleteSSOLink(linkId: string): Promise<void> {
    this.ssoLinks.delete(linkId);
  }

  async createSSOSession(data: unknown): Promise<unknown> {
    const dataRecord = data as { id: string };
    this.ssoSessions.set(dataRecord.id, data as Record<string, unknown>);
    return data;
  }

  async getSSOSession(sessionId: string): Promise<unknown> {
    return this.ssoSessions.get(sessionId) || null;
  }
}

describe('SSOService', () => {
  let ssoService: SSOService;
  let mockStorage: MockStorageAdapter;

  beforeEach(() => {
    mockStorage = new MockStorageAdapter();
    ssoService = new SSOService(
      mockStorage as unknown as import('../types').StorageAdapter,
      'test-jwt-secret',
      {
        enabled: true,
        allowMultipleProviders: true,
        autoProvision: true,
        syncUserData: true,
      }
    );
  });

  describe('OIDC Provider Management', () => {
    it('should register OIDC provider', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      expect(provider).toBeDefined();
      expect(provider.name).toBe('Google');
      expect(provider.type).toBe('oidc');
      expect(provider.client_id).toBe('google-client-id');
    });

    it('should throw error when SSO is disabled', async () => {
      const disabledService = new SSOService(
        mockStorage as unknown as import('../types').StorageAdapter,
        'secret',
        {
          enabled: false,
        }
      );

      await expect(
        disabledService.registerOIDCProvider({
          name: 'Google',
          metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
          client_id: 'google-client-id',
          client_secret: 'google-client-secret',
          redirect_uris: ['http://localhost:3000/callback'],
          type: 'oidc',
        })
      ).rejects.toThrow(ValidationError);
    });

    it('should get OIDC provider by ID', async () => {
      const created = await ssoService.registerOIDCProvider({
        name: 'GitHub',
        metadata_url: 'https://github.com/.well-known/openid-configuration',
        client_id: 'github-client-id',
        client_secret: 'github-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const retrieved = await ssoService.getProvider(created.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe('GitHub');
    });

    it('should list OIDC providers', async () => {
      await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      await ssoService.registerOIDCProvider({
        name: 'GitHub',
        metadata_url: 'https://github.com/.well-known/openid-configuration',
        client_id: 'github-client-id',
        client_secret: 'github-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const providers = await ssoService.listProviders();

      expect(providers).toHaveLength(2);
    });

    it('should update OIDC provider', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const updated = await ssoService.updateProvider(provider.id, {
        client_secret: 'new-secret',
      });

      expect(updated.client_secret).toBe('new-secret');
    });

    it('should delete OIDC provider', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      await ssoService.deleteProvider(provider.id);

      const retrieved = await ssoService.getProvider(provider.id);
      expect(retrieved).toBeNull();
    });
  });

  describe('SAML Provider Management', () => {
    it('should register SAML provider', async () => {
      const provider = await ssoService.registerSAMLProvider({
        name: 'Okta',
        idp_entity_id: 'https://okta.example.com/app/123/sso/saml',
        idp_sso_url: 'https://okta.example.com/app/123/sso/saml',
        sp_entity_id: 'http://localhost:3000/saml/metadata',
        sp_acs_url: 'http://localhost:3000/saml/acs',
        type: 'saml',
      });

      expect(provider).toBeDefined();
      expect(provider.name).toBe('Okta');
      expect(provider.type).toBe('saml');
    });
  });

  describe('SSO Links', () => {
    it('should link SSO provider to user', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const link = await ssoService.linkSSOProvider(
        'user_1',
        provider.id,
        'google-subject-123',
        'user@example.com'
      );

      expect(link).toBeDefined();
      expect(link.userId).toBe('user_1');
      expect(link.providerId).toBe(provider.id);
      expect(link.providerSubject).toBe('google-subject-123');
    });

    it('should get user SSO links', async () => {
      const provider1 = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const provider2 = await ssoService.registerOIDCProvider({
        name: 'GitHub',
        metadata_url: 'https://github.com/.well-known/openid-configuration',
        client_id: 'github-client-id',
        client_secret: 'github-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      await ssoService.linkSSOProvider('user_1', provider1.id, 'google-sub-123');
      await ssoService.linkSSOProvider('user_1', provider2.id, 'github-sub-456');

      const links = await ssoService.getUserSSOLinks('user_1');

      expect(links).toHaveLength(2);
      expect(links.some((l) => l.providerId === provider1.id)).toBe(true);
      expect(links.some((l) => l.providerId === provider2.id)).toBe(true);
    });

    it('should delete SSO link', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const link = await ssoService.linkSSOProvider('user_1', provider.id, 'google-sub-123');
      await ssoService.deleteSSOLink(link.id);

      const links = await ssoService.getUserSSOLinks('user_1');
      expect(links).toHaveLength(0);
    });
  });

  describe('SSO Sessions', () => {
    it('should create SSO session', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const session = await ssoService.createSSOSession('user_1', provider.id, 'google-sub-123');

      expect(session).toBeDefined();
      expect(session.userId).toBe('user_1');
      expect(session.providerId).toBe(provider.id);
    });

    it('should get SSO session', async () => {
      const provider = await ssoService.registerOIDCProvider({
        name: 'Google',
        metadata_url: 'https://accounts.google.com/.well-known/openid-configuration',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        type: 'oidc',
      });

      const session = await ssoService.createSSOSession('user_1', provider.id, 'google-sub-123');
      const retrieved = await ssoService.getSSOSession(session.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.userId).toBe('user_1');
    });
  });

  describe('Configuration', () => {
    it('should check if multiple providers allowed', () => {
      expect(ssoService.canLinkMultipleProviders()).toBe(true);
    });

    it('should check if auto-provisioning enabled', () => {
      expect(ssoService.isAutoProvisioningEnabled()).toBe(true);
    });

    it('should check if user data sync enabled', () => {
      expect(ssoService.isSyncUserDataEnabled()).toBe(true);
    });
  });
});
