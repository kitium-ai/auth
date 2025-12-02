import { Router } from 'express';

import type { AuthProvider } from '../config';
import type { AuthCore } from '../core';
import { createEmailRoutes } from '../email/routes';
import type { EmailAuthService } from '../email/service';
import type { EmailVerificationManager } from '../email/verification';
import { createOAuthRoutes } from '../frameworks/oauth-routes';

export type CreateApiRoutesOptions = {
  auth: AuthCore;
  providers?: AuthProvider[];
  emailService?: EmailAuthService;
  verificationManager?: EmailVerificationManager;
  basePath?: string;
};

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
  healthRouter.get('/healthz', (_request, response) => {
    response.json({ status: 'ok' });
  });
  routers.push(healthRouter);

  return routers;
}
