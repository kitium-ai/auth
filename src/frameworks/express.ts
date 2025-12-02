/**
 * Express.js integration
 */

import { getLogger } from '@kitiumai/logger';
import { err, ok } from '@kitiumai/utils-ts/runtime/result';

import type { NextFunction, Request, Response } from 'express';

import { createError } from '../errors';
import type { Result } from '@kitiumai/utils-ts/types/result';

const logger = getLogger();

/**
 * Express auth context interface
 */
export type AuthContext = {
  options?: Record<string, unknown>;
  userId?: string;
  token?: string;
};

/**
 * Extended Express Request with auth context
 */
declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

/**
 * Express auth middleware
 */
export function authMiddleware(options?: Record<string, unknown>) {
  return (request: Request, res: Response, next: NextFunction): void => {
    try {
      logger.debug('Express auth middleware', { options: options || {} });
      // Store auth context in request for downstream middleware
      request.auth = { options };
      next();
    } catch (error) {
      logger.error('Auth middleware error', { error: String(error) });
      res.status(500).json({
        error: 'auth/middleware_error',
        message: 'Authentication middleware failed',
      });
    }
  };
}

/**
 * Extract JWT token from request
 */
export function extractToken(request: Request): Result<string | null> {
  try {
    const authHeader = request.get('Authorization');
    if (!authHeader) {
      return ok(null);
    }

    if (!authHeader.startsWith('Bearer ')) {
      return err(
        createError('auth/invalid_token_format', {
          context: { reason: 'Missing Bearer prefix' },
        })
      );
    }

    const token = authHeader.slice(7);
    if (!token || token.trim().length === 0) {
      return err(
        createError('auth/invalid_token_format', {
          context: { reason: 'Empty token' },
        })
      );
    }

    return ok(token);
  } catch (error) {
    logger.error('Failed to extract token', { error: String(error) });
    return err(
      createError('auth/token_extraction_failed', {
        cause: error as Error,
        context: { operation: 'extractToken' },
      })
    );
  }
}

/**
 * Error handling middleware
 */
export function errorMiddleware(
  error: Error,
  _request: Request,
  res: Response,
  _next: NextFunction
): void {
  logger.error('Unhandled error in auth middleware', {
    error: error.message,
    stack: error.stack,
  });

  res.status(500).json({
    error: 'auth/internal_error',
    message: 'An unexpected error occurred',
  });
}
