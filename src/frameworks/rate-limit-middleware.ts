/**
 * Rate limit middleware
 * Express middleware for rate limiting
 */

import { createLogger } from '@kitiumai/logger';
import type { NextFunction, Request, Response } from 'express';

import { RateLimitError } from '../errors';
import { generateRateLimitHeaders, generateRateLimitKey, RateLimiter } from './rate-limiter';

const logger = createLogger();

/**
 * Create rate limit middleware
 */
export function createRateLimitMiddleware(
  maxRequests = 100,
  windowMs = 60000
): (request: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (request: Request, res: Response, next: NextFunction) => {
    const key = generateRateLimitKey('ip', request.ip || 'unknown');
    const allowed = limiter.isAllowed(key);

    const headers = generateRateLimitHeaders(limiter, key, maxRequests);
    Object.entries(headers).forEach(([name, value]) => {
      res.setHeader(name, value);
    });

    if (!allowed) {
      logger.warn('Rate limit exceeded', { key, ip: request.ip });
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
  maxRequests = 1000,
  windowMs = 3600000 // 1 hour
): (request: Request, res: Response, next: NextFunction) => void {
  return createRateLimitMiddleware(maxRequests, windowMs);
}

/**
 * Create per-principal rate limit middleware
 */
export function createPerPrincipalRateLimitMiddleware(
  maxRequests = 10000,
  windowMs = 3600000
): (request: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (request: Request, res: Response, next: NextFunction) => {
    const userId = (request as { user?: { id: string } }).user?.id;
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
  maxRequests = 50,
  windowMs = 60000
): (request: Request, res: Response, next: NextFunction) => void {
  const limiter = new RateLimiter(maxRequests, windowMs);

  return (request: Request, res: Response, next: NextFunction) => {
    const userId = (request as { user?: { id?: string } }).user?.id || 'anonymous';
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
