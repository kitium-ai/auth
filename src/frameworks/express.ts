/**
 * Express.js integration
 */

import { Request, Response, NextFunction } from 'express';
import { getLogger } from '@kitiumai/logger';

const logger = getLogger();

/**
 * Express auth middleware
 */
export function authMiddleware(options?: Record<string, unknown>) {
  return (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Express auth middleware');
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
