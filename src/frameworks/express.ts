/**
 * Express.js integration
 */

import { Request, Response, NextFunction } from 'express';
import { createLogger } from '@kitiumai/logger';

const logger = createLogger();

/**
 * Express auth middleware
 */
export function authMiddleware(options?: Record<string, unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Express auth middleware', { options: options || {} });
    // Store auth context in request for downstream middleware
    (req as { auth?: { options?: Record<string, unknown> } }).auth = { options };
    // Store response object for potential use in downstream handlers
    (res as { authContext?: { options?: Record<string, unknown> } }).authContext = { options };
    next();
  };
}

/**
 * Extract JWT token from request
 */
export function extractToken(req: Request): string | null {
  const authHeader = req.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}
