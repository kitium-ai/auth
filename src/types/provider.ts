/**
 * Provider types for authentication
 */

export type ProviderType = 'oauth' | 'email' | 'saml' | 'magic-link';

export type Provider = {
  id: string;
  type: ProviderType;
  enabled: boolean;
  name: string;
  metadata?: Record<string, unknown>;
};

export type OAuthProvider = {
  type: 'oauth';
  clientId: string;
  clientSecret: string;
  discoveryUrl?: string;
  authorizationUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  scope?: string[];
  authorizationMethod?: 'header' | 'body';
} & Provider;

export type EmailProvider = {
  type: 'email';
  fromEmail: string;
  fromName?: string;
  replyTo?: string;
} & Provider;

export type SAMLProvider = {
  type: 'saml';
  entryPoint: string;
  issuer: string;
  cert: string;
  identifierFormat?: string;
  wantAssertionsSigned?: boolean;
} & Provider;

export type MagicLinkProvider = {
  type: 'magic-link';
  tokenExpiryMinutes?: number;
} & Provider;

export type AuthProvider = OAuthProvider | EmailProvider | SAMLProvider | MagicLinkProvider;
