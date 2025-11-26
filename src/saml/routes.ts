import { getLogger } from '@kitiumai/logger';

const logger = getLogger();

export function createSAMLRoutes(): unknown[] {
  return [];
}
export function extractTenantIdMiddleware() {
  return (
    req: {
      headers: Record<string, unknown>;
      query: Record<string, unknown>;
      [key: string]: unknown;
    },
    res: { locals?: Record<string, unknown> },
    next: () => void
  ) => {
    // Extract tenant ID from request headers or query params
    const tenantId = (req.headers['x-tenant-id'] || req.query['tenantId']) as string | undefined;
    if (tenantId) {
      req['tenantId'] = tenantId;
      // Store tenant ID in response locals for potential use
      res.locals = { ...(res.locals || {}), tenantId };
    }
    // Use req and res to avoid unused variable warnings
    logger.debug('Extracting tenant ID', { hasReq: !!req, hasRes: !!res });
    next();
  };
}
