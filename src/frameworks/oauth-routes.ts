/* eslint-disable no-restricted-imports */
/* eslint-disable @typescript-eslint/naming-convention */
import { Router, type Request, type Response, type NextFunction } from 'express';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { createLogger } from '@kitiumai/logger';
import type { AuthProvider } from '../config';
import { OAUTH_PROVIDER_PRESETS } from '../providers/oauth-presets';
import { OAuthManager, PKCEGenerator, type OAuthTokenResponse } from '../oauth';

export interface CreateOAuthRoutesOptions {
  providers: AuthProvider[];
  basePath?: string;
  defaultRedirectUri?: string;
}

interface NormalizedOAuthProvider {
  id: string;
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scopes: string[];
}

interface PendingState {
  state: string;
  expiresAt: Date;
  providerId: string;
  codeVerifier: string;
}

const logger = createLogger();

export async function createOAuthRoutes(options: CreateOAuthRoutesOptions): Promise<Router> {
  const providers = normalizeProviders(options.providers, options.defaultRedirectUri);
  const router = Router();
  const stateStore = new Map<string, PendingState>();
  const basePath = options.basePath || '/auth/oauth';

  router.get(`${basePath}/providers`, (_req, res) => {
    res.json(
      providers.map((provider) => ({
        id: provider.id,
        name: provider.name,
        scopes: provider.scopes,
      }))
    );
  });

  router.get(
    `${basePath}/:provider/start`,
    wrapAsync(async (req, res) => {
      const providerParam = req.params['provider'];
      if (!providerParam) {
        res.status(400).json({ error: 'Missing provider identifier' });
        return;
      }
      const provider = findProvider(providers, providerParam);
      const { codeVerifier, codeChallenge } = PKCEGenerator.generate();
      const stateRecord = OAuthManager.generateState();
      stateRecord.redirectUri = provider.redirectUri;

      stateStore.set(stateRecord.state, {
        state: stateRecord.state,
        expiresAt: stateRecord.expiresAt,
        providerId: provider.id,
        codeVerifier,
      });

      const authorizationUrl = OAuthManager.generateAuthorizationUrl(provider.authorizationUrl, {
        clientId: provider.clientId,
        redirectUri: provider.redirectUri,
        scopes: provider.scopes,
        state: stateRecord.state,
        codeChallenge,
        codeChallengeMethod: 'S256',
      });

      res.json({
        authorizationUrl,
        state: stateRecord.state,
      });
    })
  );

  router.post(
    `${basePath}/:provider/callback`,
    wrapAsync(async (req, res) => {
      const providerParam = req.params['provider'];
      if (!providerParam) {
        res.status(400).json({ error: 'Missing provider identifier' });
        return;
      }
      const provider = findProvider(providers, providerParam);
      const { code, state } = req.body as { code?: string; state?: string };
      if (!code || !state) {
        res.status(400).json({ error: 'Missing authorization code or state' });
        return;
      }

      const pendingState = stateStore.get(state);
      stateStore.delete(state);

      if (
        !pendingState ||
        pendingState.providerId !== provider.id ||
        pendingState.expiresAt < new Date()
      ) {
        res.status(400).json({ error: 'Invalid or expired OAuth state' });
        return;
      }

      const tokenResponse = await exchangeAuthorizationCode(
        provider,
        code,
        pendingState.codeVerifier
      );
      res.json({
        tokens: tokenResponse,
      });
    })
  );

  return router;
}

function normalizeProviders(
  providers: AuthProvider[],
  defaultRedirectUri?: string
): NormalizedOAuthProvider[] {
  return providers
    .filter((provider) => provider.type === 'oauth')
    .map((provider) => {
      const config = provider.config || {};
      const preset = OAUTH_PROVIDER_PRESETS[provider.id];
      const authorizationUrl =
        (config['authorizationUrl'] as string) ||
        preset?.authorizationUrl ||
        'https://example.com/oauth/authorize';
      const tokenUrl =
        (config['tokenUrl'] as string) || preset?.tokenUrl || 'https://example.com/oauth/token';
      const redirectUri =
        (config['redirectUri'] as string) ||
        defaultRedirectUri ||
        'http://localhost:3000/api/auth/callback';
      const scopes = (config['scopes'] as string[]) ||
        preset?.defaultScopes || ['openid', 'profile', 'email'];
      const clientId = config['clientId'] as string;

      if (!clientId) {
        throw new Error(`OAuth provider ${provider.id} is missing clientId`);
      }

      return {
        id: provider.id,
        name: provider.name,
        authorizationUrl,
        tokenUrl,
        clientId,
        clientSecret: config['clientSecret'] as string | undefined,
        redirectUri,
        scopes,
      };
    });
}

function findProvider(
  providers: NormalizedOAuthProvider[],
  providerId: string
): NormalizedOAuthProvider {
  const normalizedId = providerId.toLowerCase();
  const provider = providers.find((entry) => entry.id.toLowerCase() === normalizedId);
  if (!provider) {
    throw new Error(`Unknown OAuth provider: ${providerId}`);
  }

  return provider;
}

async function exchangeAuthorizationCode(
  provider: NormalizedOAuthProvider,
  code: string,
  codeVerifier?: string
): Promise<OAuthTokenResponse> {
  const params = new URLSearchParams();
  params.set('grant_type', 'authorization_code');
  params.set('code', code);
  params.set('redirect_uri', provider.redirectUri);
  params.set('client_id', provider.clientId);

  if (provider.clientSecret) {
    params.set('client_secret', provider.clientSecret);
  }

  if (codeVerifier) {
    params.set('code_verifier', codeVerifier);
  }

  const responseBody = await httpFormPost(provider.tokenUrl, params);
  return JSON.parse(responseBody) as OAuthTokenResponse;
}

async function httpFormPost(url: string, params: URLSearchParams): Promise<string> {
  const body = params.toString();
  const target = new URL(url);

  return new Promise<string>((resolve, reject) => {
    const request = https.request(
      {
        method: 'POST',
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body).toString(),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(chunk as Buffer));
        response.on('end', () => {
          const payload = Buffer.concat(chunks).toString('utf8');
          if ((response.statusCode ?? 500) >= 400) {
            reject(new Error(`OAuth token request failed: ${response.statusCode} ${payload}`));
            return;
          }
          resolve(payload);
        });
      }
    );

    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

function wrapAsync(handler: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    handler(req, res).catch((error) => {
      logger.error('OAuth route error', { error: String(error) });
      next(error);
    });
  };
}
