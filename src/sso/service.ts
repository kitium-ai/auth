import { nanoid } from 'nanoid';
import * as jwt from 'jsonwebtoken';
import { getLogger } from '@kitiumai/logger';
import {
  SSOConfig,
  OIDCProvider,
  SAMLProvider,
  SSOSession,
  SSOLink,
  OIDCTokenResponse,
  OIDCUserInfo,
} from '../types';
import { ValidationError, AuthenticationError, NotFoundError } from '../errors';
import { StorageAdapter } from '../types';

/**
 * SSO (Single Sign-On) Service
 * Manages OIDC providers, SAML, and multi-provider SSO sessions
 */
export class SSOService {
  private storage: StorageAdapter;
  private config: SSOConfig;
  private jwtSecret: string;
  private logger = getLogger();

  constructor(storage: StorageAdapter, jwtSecret: string, config: SSOConfig = { enabled: false }) {
    this.storage = storage;
    this.jwtSecret = jwtSecret;
    this.config = config;
    this.logger.debug('SSOService initialized', { enabled: config.enabled });
  }

  /**
   * Register an OIDC provider
   */
  async registerOIDCProvider(
    provider: Omit<OIDCProvider, 'createdAt' | 'updatedAt'>
  ): Promise<OIDCProvider> {
    if (!this.config.enabled) {
      this.logger.warn('OIDC provider registration attempted when SSO disabled');
      throw new ValidationError({
        code: 'auth/sso_not_enabled',
        message: 'SSO is not enabled',
      });
    }

    this.logger.debug('Registering OIDC provider', {
      name: provider.name,
      orgId: (provider as any).orgId,
    });

    const providerId = `oidc_${nanoid()}`;
    const now = new Date();

    const oidcProvider: OIDCProvider = {
      ...provider,
      id: providerId,
      createdAt: now,
      updatedAt: now,
    };

    if (!this.storage.createSSOProvider) {
      throw new ValidationError({
        code: 'auth/sso_provider_creation_not_supported',
        message: 'SSO provider creation is not supported',
      });
    }

    return this.storage.createSSOProvider(oidcProvider);
  }

  /**
   * Register a SAML provider
   */
  async registerSAMLProvider(
    provider: Omit<SAMLProvider, 'createdAt' | 'updatedAt'>
  ): Promise<SAMLProvider> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/sso_not_enabled',
        message: 'SSO is not enabled',
      });
    }

    const providerId = `saml_${nanoid()}`;
    const now = new Date();

    const samlProvider: SAMLProvider = {
      ...provider,
      id: providerId,
      createdAt: now,
      updatedAt: now,
    };

    if (!this.storage.createSSOProvider) {
      throw new ValidationError({
        code: 'auth/sso_provider_creation_not_supported',
        message: 'SSO provider creation is not supported',
      });
    }

    return this.storage.createSSOProvider(samlProvider);
  }

  /**
   * Get SSO provider by ID
   */
  async getProvider(providerId: string): Promise<OIDCProvider | SAMLProvider | null> {
    if (!this.storage.getSSOProvider) {
      return null;
    }

    return this.storage.getSSOProvider(providerId);
  }

  /**
   * Update SSO provider
   */
  async updateProvider(
    providerId: string,
    updates: Partial<OIDCProvider | SAMLProvider>
  ): Promise<OIDCProvider | SAMLProvider> {
    if (!this.storage.updateSSOProvider) {
      throw new ValidationError({
        code: 'auth/sso_provider_update_not_supported',
        message: 'SSO provider update is not supported',
      });
    }

    return this.storage.updateSSOProvider(providerId, {
      ...updates,
      updatedAt: new Date(),
    });
  }

  /**
   * Delete SSO provider
   */
  async deleteProvider(providerId: string): Promise<void> {
    if (!this.storage.deleteSSOProvider) {
      throw new ValidationError({
        code: 'auth/sso_provider_deletion_not_supported',
        message: 'SSO provider deletion is not supported',
      });
    }

    return this.storage.deleteSSOProvider(providerId);
  }

  /**
   * List all SSO providers (optionally filtered by org)
   */
  async listProviders(orgId?: string): Promise<(OIDCProvider | SAMLProvider)[]> {
    if (!this.storage.listSSOProviders) {
      return [];
    }

    return this.storage.listSSOProviders(orgId);
  }

  /**
   * Generate OIDC authorization URL
   */
  async getOIDCAuthorizationUrl(
    providerId: string,
    state: string,
    nonce: string,
    redirectUri?: string
  ): Promise<string> {
    const provider = (await this.getProvider(providerId)) as OIDCProvider | null;
    if (!provider || provider.type !== 'oidc') {
      throw new NotFoundError({
        code: 'auth/oidc_provider_not_found',
        message: `OIDC provider not found: ${providerId}`,
        context: { providerId },
      });
    }

    // Fetch OIDC metadata
    const metadata = await this.fetchOIDCMetadata(provider.metadata_url);

    const params = new URLSearchParams({
      client_id: provider.client_id,
      redirect_uri: redirectUri || provider.redirect_uris[0],
      response_type: provider.response_type || 'code',
      scope: (provider.scopes || ['openid', 'profile', 'email']).join(' '),
      state,
      nonce,
    });

    return `${metadata.authorization_endpoint}?${params.toString()}`;
  }

  /**
   * Exchange OIDC authorization code for tokens
   */
  async exchangeOIDCCode(
    providerId: string,
    code: string,
    redirectUri: string
  ): Promise<OIDCTokenResponse & { userInfo: OIDCUserInfo }> {
    const provider = (await this.getProvider(providerId)) as OIDCProvider | null;
    if (!provider || provider.type !== 'oidc') {
      throw new NotFoundError({
        code: 'auth/oidc_provider_not_found',
        message: `OIDC provider not found: ${providerId}`,
        context: { providerId },
      });
    }

    const metadata = await this.fetchOIDCMetadata(provider.metadata_url);

    // In production, make actual HTTP request to token endpoint
    // const tokenResponse = await fetch(metadata.token_endpoint, {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    //   body: new URLSearchParams({
    //     grant_type: 'authorization_code',
    //     code,
    //     redirect_uri: redirectUri,
    //     client_id: provider.client_id,
    //     client_secret: provider.client_secret
    //   })
    // })

    // Mock response for now
    const tokenResponse: OIDCTokenResponse = {
      access_token: 'mock_access_token',
      token_type: 'Bearer',
      expires_in: 3600,
    };

    // Fetch user info
    const userInfo = await this.getOIDCUserInfo(provider, tokenResponse.access_token);

    return {
      ...tokenResponse,
      userInfo,
    };
  }

  /**
   * Get OIDC user info
   */
  private async getOIDCUserInfo(
    provider: OIDCProvider,
    accessToken: string
  ): Promise<OIDCUserInfo> {
    const metadata = await this.fetchOIDCMetadata(provider.metadata_url);

    // In production, make actual HTTP request to userinfo endpoint
    // const response = await fetch(metadata.userinfo_endpoint, {
    //   headers: { Authorization: `Bearer ${accessToken}` }
    // })
    // return response.json()

    // Mock response for now
    return {
      sub: `${provider.id}_user_${nanoid()}`,
      name: 'Test User',
      email: 'test@example.com',
      email_verified: true,
      picture: 'https://example.com/photo.jpg',
    };
  }

  /**
   * Fetch and cache OIDC metadata
   */
  private async fetchOIDCMetadata(metadataUrl: string): Promise<any> {
    // In production, cache this and implement refresh logic
    // For now, return mock metadata
    return {
      authorization_endpoint: 'https://provider.example.com/authorize',
      token_endpoint: 'https://provider.example.com/token',
      userinfo_endpoint: 'https://provider.example.com/userinfo',
      jwks_uri: 'https://provider.example.com/.well-known/jwks.json',
      issuer: 'https://provider.example.com',
    };
  }

  /**
   * Link SSO provider to user
   */
  async linkSSOProvider(
    userId: string,
    providerId: string,
    providerSubject: string,
    providerEmail?: string,
    autoProvisioned: boolean = false
  ): Promise<SSOLink> {
    const provider = await this.getProvider(providerId);
    if (!provider) {
      throw new NotFoundError({
        code: 'auth/sso_provider_not_found',
        message: `SSO provider not found: ${providerId}`,
        context: { providerId },
      });
    }

    const linkId = `sso_link_${nanoid()}`;
    const now = new Date();

    const ssoLink: SSOLink = {
      id: linkId,
      userId,
      providerId,
      providerType: provider.type as any,
      providerSubject,
      providerEmail,
      autoProvisioned,
      linkedAt: now,
      lastAuthAt: now,
    };

    if (!this.storage.createSSOLink) {
      throw new ValidationError({
        code: 'auth/sso_link_creation_not_supported',
        message: 'SSO link creation is not supported',
      });
    }

    return this.storage.createSSOLink(ssoLink);
  }

  /**
   * Get SSO link by provider subject
   */
  async getSSOLinkByProviderSubject(
    providerId: string,
    providerSubject: string
  ): Promise<SSOLink | null> {
    const links = await this.getUserSSOLinks('');
    return (
      links.find((l) => l.providerId === providerId && l.providerSubject === providerSubject) ||
      null
    );
  }

  /**
   * Get all SSO links for a user
   */
  async getUserSSOLinks(userId: string): Promise<SSOLink[]> {
    if (!this.storage.getUserSSOLinks) {
      return [];
    }

    return this.storage.getUserSSOLinks(userId);
  }

  /**
   * Delete SSO link
   */
  async deleteSSOLink(linkId: string): Promise<void> {
    if (!this.storage.deleteSSOLink) {
      throw new ValidationError({
        code: 'auth/sso_link_deletion_not_supported',
        message: 'SSO link deletion is not supported',
      });
    }

    return this.storage.deleteSSOLink(linkId);
  }

  /**
   * Create SSO session
   */
  async createSSOSession(
    userId: string,
    providerId: string,
    providerSubject: string
  ): Promise<SSOSession> {
    const provider = await this.getProvider(providerId);
    if (!provider) {
      throw new NotFoundError({
        code: 'auth/sso_provider_not_found',
        message: `SSO provider not found: ${providerId}`,
        context: { providerId },
      });
    }

    const sessionId = `sso_session_${nanoid()}`;
    const now = new Date();

    const ssoSession: SSOSession = {
      id: sessionId,
      userId,
      providerId,
      providerType: provider.type as any,
      providerSubject,
      expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000), // 24 hours
      linkedAt: now,
      lastAuthAt: now,
    };

    if (!this.storage.createSSOSession) {
      throw new ValidationError({
        code: 'auth/sso_session_creation_not_supported',
        message: 'SSO session creation is not supported',
      });
    }

    return this.storage.createSSOSession(ssoSession);
  }

  /**
   * Get SSO session
   */
  async getSSOSession(sessionId: string): Promise<SSOSession | null> {
    if (!this.storage.getSSOSession) {
      return null;
    }

    return this.storage.getSSOSession(sessionId);
  }

  /**
   * Check if multiple SSO providers are allowed
   */
  canLinkMultipleProviders(): boolean {
    return this.config.allowMultipleProviders || false;
  }

  /**
   * Check if auto-provisioning is enabled
   */
  isAutoProvisioningEnabled(): boolean {
    return this.config.autoProvision || false;
  }

  /**
   * Check if user data sync is enabled
   */
  isSyncUserDataEnabled(): boolean {
    return this.config.syncUserData || false;
  }
}
