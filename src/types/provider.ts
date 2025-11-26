/**
 * Provider types for authentication
 */

export type ProviderType = 'oauth' | 'email' | 'saml' | 'magic-link';

export interface Provider {
  id: string;
  type: ProviderType;
  enabled: boolean;
  name: string;
  metadata?: Record<string, unknown>;
}

export interface OAuthProvider extends Provider {
  type: 'oauth';
  clientId: string;
  clientSecret: string;
  discoveryUrl?: string;
  authorizationUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  scope?: string[];
  authorizationMethod?: 'header' | 'body';
}

export interface EmailProvider extends Provider {
  type: 'email';
  fromEmail: string;
  fromName?: string;
  replyTo?: string;
}

export interface SAMLProvider extends Provider {
  type: 'saml';
  entryPoint: string;
  issuer: string;
  cert: string;
  identifierFormat?: string;
  wantAssertionsSigned?: boolean;
}

export interface MagicLinkProvider extends Provider {
  type: 'magic-link';
  tokenExpiryMinutes?: number;
}

export type AuthProvider = OAuthProvider | EmailProvider | SAMLProvider | MagicLinkProvider;
