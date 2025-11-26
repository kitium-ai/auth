/* eslint-disable no-restricted-imports */
import { Router } from 'express';
import type { AuthCore } from '../core';
import type { AuthProvider } from '../config';
import { EmailAuthService } from '../email/service';
import { EmailVerificationManager } from '../email/verification';
import { createEmailRoutes } from '../email/routes';
import { createOAuthRoutes } from '../frameworks/oauth-routes';

export interface CreateApiRoutesOptions {
  auth: AuthCore;
  providers?: AuthProvider[];
  emailService?: EmailAuthService;
  verificationManager?: EmailVerificationManager;
  basePath?: string;
}

export async function createApiRoutes(options: CreateApiRoutesOptions): Promise<Router[]> {
  const routers: Router[] = [];
  const emailRouter = await createEmailRoutes({
    auth: options.auth,
    emailService: options.emailService,
    verificationManager: options.verificationManager,
    basePath: options.basePath ? `${options.basePath}/email` : undefined,
  });
  routers.push(emailRouter);

  if (options.providers?.some((provider) => provider.type === 'oauth')) {
    routers.push(
      await createOAuthRoutes({
        providers: options.providers,
        basePath: options.basePath ? `${options.basePath}/oauth` : undefined,
      })
    );
  }

  const healthRouter = Router();
  healthRouter.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
  });
  routers.push(healthRouter);

  return routers;
}
