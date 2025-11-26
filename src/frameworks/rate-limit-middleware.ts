/**
 * Rate limit middleware
 * Express middleware for rate limiting
 */

/* eslint-disable no-restricted-imports */
import { Request, Response, NextFunction } from 'express';
import { getLogger } from '@kitiumai/logger';
import { RateLimiter, generateRateLimitKey, generateRateLimitHeaders } from './rate-limiter';
import { RateLimitError } from '../errors';

const logger = getLogger();

/**
 * Create rate limit middleware
 */
export function createRateLimitMiddleware(
  maxRequests: number = 100,
  windowMs: number = 60000
): (req: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (req: Request, res: Response, next: NextFunction) => {
    const key = generateRateLimitKey('ip', req.ip || 'unknown');
    const allowed = limiter.isAllowed(key);

    const headers = generateRateLimitHeaders(limiter, key, maxRequests);
    Object.entries(headers).forEach(([name, value]) => {
      res.setHeader(name, value);
    });

    if (!allowed) {
      logger.warn('Rate limit exceeded', { key, ip: req.ip });
      throw new RateLimitError({
        code: 'auth/rate_limit_exceeded',
        message: 'Too many requests',
        severity: 'warning',
        retryable: true,
      });
    }

    next();
  };
}

/**
 * Create public rate limit middleware (more permissive)
 */
export function createPublicRateLimitMiddleware(
  maxRequests: number = 1000,
  windowMs: number = 3600000 // 1 hour
): (req: Request, res: Response, next: NextFunction) => void {
  return createRateLimitMiddleware(maxRequests, windowMs);
}

/**
 * Create per-principal rate limit middleware
 */
export function createPerPrincipalRateLimitMiddleware(
  maxRequests: number = 10000,
  windowMs: number = 3600000
): (req: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (req: Request, res: Response, next: NextFunction) => {
    const userId = (req as { user?: { id: string } }).user?.id;
    const key = generateRateLimitKey('user', userId || 'anonymous');
    const allowed = limiter.isAllowed(key);

    const headers = generateRateLimitHeaders(limiter, key, maxRequests);
    Object.entries(headers).forEach(([name, value]) => {
      res.setHeader(name, value);
    });

    if (!allowed) {
      logger.warn('User rate limit exceeded', { key, userId });
      throw new RateLimitError({
        code: 'auth/user_rate_limit_exceeded',
        message: 'Rate limit exceeded for this user',
        severity: 'warning',
        retryable: true,
      });
    }

    next();
  };
}

/**
 * Create endpoint-specific rate limit middleware
 */
export function createEndpointRateLimitMiddleware(
  endpoint: string,
  maxRequests: number = 50,
  windowMs: number = 60000
): (req: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (req: Request, res: Response, next: NextFunction) => {
    const userId = (req as { user?: { id?: string } }).user?.id || 'anonymous';
    const key = generateRateLimitKey(`endpoint:${endpoint}`, userId);
    const allowed = limiter.isAllowed(key);

    const headers = generateRateLimitHeaders(limiter, key, maxRequests);
    Object.entries(headers).forEach(([name, value]) => {
      res.setHeader(name, value);
    });

    if (!allowed) {
      logger.warn('Endpoint rate limit exceeded', { endpoint, userId });
      throw new RateLimitError({
        code: 'auth/endpoint_rate_limit_exceeded',
        message: `Rate limit exceeded for ${endpoint}`,
        severity: 'warning',
        retryable: true,
        context: { endpoint },
      });
    }

    next();
  };
}
