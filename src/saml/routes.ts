import { createLogger } from '@kitiumai/logger';

const logger = createLogger();

export function createSAMLRoutes(): unknown[] {
  return [];
}
export function extractTenantIdMiddleware() {
  return (
    request: {
      headers: Record<string, unknown>;
      query: Record<string, unknown>;
      [key: string]: unknown;
    },
    res: { locals?: Record<string, unknown> },
    next: () => void
  ) => {
    // Extract tenant ID from request headers or query params
    const tenantId = (request.headers['x-tenant-id'] || request.query['tenantId']) as
      | string
      | undefined;
    if (tenantId) {
      request['tenantId'] = tenantId;
      // Store tenant ID in response locals for potential use
      res.locals = { ...(res.locals || {}), tenantId };
    }
    // Use req and res to avoid unused variable warnings
    logger.debug('Extracting tenant ID', { hasReq: !!request, hasRes: !!res });
    next();
  };
}
