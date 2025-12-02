/**
 * OAuth 2.0 utilities
 * PKCE, state management, and token handling
 */

import * as crypto from 'node:crypto';

/**
 * OAuth state for preventing CSRF attacks
 */
export type OAuthState = {
  state: string;
  nonce: string;
  redirectUri: string;
  createdAt: Date;
  expiresAt: Date;
};

/**
 * OAuth authorization request
 */
export type OAuthAuthorizationRequest = {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
};

/**
 * OAuth token response
 */

export type OAuthTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
};

/**
 * PKCE Code Verifier and Challenge generator
 */
export class PKCEGenerator {
  /**
   * Generate a random code verifier
   */
  static generateCodeVerifier(): string {
    // Code verifier must be between 43-128 characters
    const randomBytes = crypto.randomBytes(32).toString('base64url');
    return randomBytes.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '').substring(0, 128);
  }

  /**
   * Generate code challenge from verifier using SHA256
   */
  static generateCodeChallenge(codeVerifier: string): string {
    return crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * Generate both verifier and challenge
   */
  static generate(): { codeVerifier: string; codeChallenge: string } {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    return { codeVerifier, codeChallenge };
  }
}

/**
 * OAuth Manager for handling OAuth flows
 */
export class OAuthManager {
  /**
   * Generate OAuth state
   */
  static generateState(expiresInMinutes = 10): OAuthState {
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + expiresInMinutes * 60000);

    return {
      state,
      nonce,
      redirectUri: '',
      createdAt,
      expiresAt,
    };
  }

  /**
   * Verify state is valid and not expired
   */
  static verifyState(state: OAuthState, currentState: string): boolean {
    const isExpired = new Date() > state.expiresAt;
    const isMatching = crypto.timingSafeEqual(Buffer.from(state.state), Buffer.from(currentState));

    return !isExpired && isMatching;
  }

  /**
   * Generate authorization URL
   */
  static generateAuthorizationUrl(
    authorizationEndpoint: string,
    request: OAuthAuthorizationRequest
  ): string {
    const parameters = new URLSearchParams({
      client_id: request.clientId,

      redirect_uri: request.redirectUri,
      scope: request.scopes.join(' '),
      state: request.state,

      response_type: 'code',
    });

    if (request.nonce) {
      parameters.append('nonce', request.nonce);
    }

    if (request.codeChallenge && request.codeChallengeMethod) {
      parameters.append('code_challenge', request.codeChallenge);
      parameters.append('code_challenge_method', request.codeChallengeMethod);
    }

    return `${authorizationEndpoint}?${parameters.toString()}`;
  }
}
