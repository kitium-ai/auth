/**
 * Pre-configured OAuth providers
 * Common OAuth providers with default configurations
 */

import { AuthProvider } from '../config';

export interface OAuthProviderPreset {
  id: string;
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
  defaultScopes: string[];
}

/**
 * Google OAuth 2.0 provider preset
 */
export const GOOGLE_PROVIDER: OAuthProviderPreset = {
  id: 'google',
  name: 'Google',
  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
  scopes: ['openid', 'profile', 'email'],
  defaultScopes: ['openid', 'profile', 'email'],
};

/**
 * GitHub OAuth provider preset
 */
export const GITHUB_PROVIDER: OAuthProviderPreset = {
  id: 'github',
  name: 'GitHub',
  authorizationUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  scopes: ['read:user', 'user:email'],
  defaultScopes: ['read:user', 'user:email'],
};

/**
 * Microsoft/Azure AD OAuth provider preset
 */
export const MICROSOFT_PROVIDER: OAuthProviderPreset = {
  id: 'microsoft',
  name: 'Microsoft',
  authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
  scopes: ['openid', 'profile', 'email', 'User.Read'],
  defaultScopes: ['openid', 'profile', 'email', 'User.Read'],
};

/**
 * Facebook OAuth provider preset
 */
export const FACEBOOK_PROVIDER: OAuthProviderPreset = {
  id: 'facebook',
  name: 'Facebook',
  authorizationUrl: 'https://www.facebook.com/v18.0/dialog/oauth',
  tokenUrl: 'https://graph.facebook.com/v18.0/oauth/access_token',
  userInfoUrl: 'https://graph.facebook.com/v18.0/me',
  scopes: ['email', 'public_profile'],
  defaultScopes: ['email', 'public_profile'],
};

/**
 * Apple OAuth provider preset
 */
export const APPLE_PROVIDER: OAuthProviderPreset = {
  id: 'apple',
  name: 'Apple',
  authorizationUrl: 'https://appleid.apple.com/auth/authorize',
  tokenUrl: 'https://appleid.apple.com/auth/token',
  userInfoUrl: '', // Apple doesn't provide userinfo endpoint
  scopes: ['name', 'email'],
  defaultScopes: ['name', 'email'],
};

/**
 * Twitter OAuth provider preset
 */
export const TWITTER_PROVIDER: OAuthProviderPreset = {
  id: 'twitter',
  name: 'Twitter',
  authorizationUrl: 'https://twitter.com/i/oauth2/authorize',
  tokenUrl: 'https://api.twitter.com/2/oauth2/token',
  userInfoUrl: 'https://api.twitter.com/2/users/me',
  scopes: ['tweet.read', 'users.read'],
  defaultScopes: ['tweet.read', 'users.read'],
};

/**
 * Discord OAuth provider preset
 */
export const DISCORD_PROVIDER: OAuthProviderPreset = {
  id: 'discord',
  name: 'Discord',
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  scopes: ['identify', 'email'],
  defaultScopes: ['identify', 'email'],
};

/**
 * LinkedIn OAuth provider preset
 */
export const LINKEDIN_PROVIDER: OAuthProviderPreset = {
  id: 'linkedin',
  name: 'LinkedIn',
  authorizationUrl: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
  userInfoUrl: 'https://api.linkedin.com/v2/userinfo',
  scopes: ['openid', 'profile', 'email'],
  defaultScopes: ['openid', 'profile', 'email'],
};

/**
 * All available OAuth provider presets
 */
export const OAUTH_PROVIDER_PRESETS: Record<string, OAuthProviderPreset> = {
  google: GOOGLE_PROVIDER,
  github: GITHUB_PROVIDER,
  microsoft: MICROSOFT_PROVIDER,
  facebook: FACEBOOK_PROVIDER,
  apple: APPLE_PROVIDER,
  twitter: TWITTER_PROVIDER,
  discord: DISCORD_PROVIDER,
  linkedin: LINKEDIN_PROVIDER,
};

/**
 * Create an AuthProvider from an OAuth preset
 */
export function createOAuthProviderFromPreset(
  presetId: string,
  clientId: string,
  clientSecret: string,
  redirectUri: string,
  options?: {
    scopes?: string[];
    customScopes?: string[];
  }
): AuthProvider {
  const preset = OAUTH_PROVIDER_PRESETS[presetId.toLowerCase()];
  if (!preset) {
    throw new Error(`Unknown OAuth provider preset: ${presetId}`);
  }

  const scopes = options?.customScopes || options?.scopes || preset.defaultScopes;

  return {
    id: preset.id,
    name: preset.name,
    type: 'oauth',
    enabled: true,
    config: {
      clientId,
      clientSecret,
      redirectUri,
      authorizationUrl: preset.authorizationUrl,
      tokenUrl: preset.tokenUrl,
      userInfoUrl: preset.userInfoUrl,
      scopes,
    },
  };
}

/**
 * Get available OAuth provider presets
 */
export function getAvailableOAuthProviders(): string[] {
  return Object.keys(OAUTH_PROVIDER_PRESETS);
}

/**
 * Check if a provider preset exists
 */
export function hasOAuthProviderPreset(providerId: string): boolean {
  return providerId.toLowerCase() in OAUTH_PROVIDER_PRESETS;
}
