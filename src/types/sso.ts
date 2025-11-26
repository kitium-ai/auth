// Single Sign-On (SSO) types for enhanced OIDC and multi-provider support

export type SSOProviderType = 'saml' | 'oidc' | 'oauth';

export interface SSOConfig {
  enabled: boolean;
  allowMultipleProviders?: boolean; // Allow linking multiple SSO providers
  autoProvision?: boolean; // Auto-create users on first login
  defaultPlan?: string; // Plan to assign to auto-provisioned users
  syncUserData?: boolean; // Sync user profile data from provider
}

export interface OIDCProvider {
  id: string;
  type: 'oidc';
  name: string;
  metadata_url: string; // OIDC provider metadata endpoint
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  scopes?: string[]; // Default: ['openid', 'profile', 'email']
  response_type?: string; // Default: 'code'
  token_endpoint_auth_method?: string; // Default: 'client_secret_basic'
  claim_mapping?: {
    nameAttribute?: string; // Default: 'name'
    emailAttribute?: string; // Default: 'email'
    pictureAttribute?: string; // Default: 'picture'
    subAttribute?: string; // Default: 'sub'
  };
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface SAMLProvider {
  id: string;
  type: 'saml';
  name: string;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_slo_url?: string;
  idp_certificate?: string; // Public certificate for signature verification
  sp_entity_id: string;
  sp_acs_url: string;
  sp_slo_url?: string;
  signing_cert?: string;
  signing_key?: string;
  encryption_enabled?: boolean;
  force_authn?: boolean; // Force re-authentication
  allow_unencrypted_assertion?: boolean;
  attribute_mapping?: {
    nameAttribute?: string; // Default: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
    emailAttribute?: string; // Default: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
    pictureAttribute?: string;
    subAttribute?: string; // Default: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'
  };
  metadata?: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

export interface SSOSession {
  id: string;
  userId: string;
  providerId: string;
  providerType: SSOProviderType;
  providerSubject: string; // Subject ID from provider
  sessionToken?: string; // Session token from provider
  expiresAt: Date;
  linkedAt: Date;
  lastAuthAt: Date;
}

export interface SSOLink {
  id: string;
  userId: string;
  providerId: string;
  providerType: SSOProviderType;
  providerSubject: string; // Remote user ID from provider
  providerEmail?: string; // Email from provider
  autoProvisioned?: boolean;
  metadata?: Record<string, any>;
  linkedAt: Date;
  lastAuthAt: Date;
}

export interface OIDCTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface OIDCUserInfo {
  sub: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  locale?: string;
  metadata?: Record<string, any>;
}

export interface SAMLAssertion {
  nameID: string;
  sessionIndex?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
  attributes?: Record<string, any>;
  metadata?: Record<string, any>;
}

// Database record types
export interface OIDCProviderRecord extends OIDCProvider {}

export interface SAMLProviderRecord extends SAMLProvider {}

export interface SSOSessionRecord extends SSOSession {}

export interface SSOLinkRecord extends SSOLink {}
