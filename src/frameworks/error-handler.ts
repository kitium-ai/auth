/**
 * Error handling middleware
 * Global error handling for Express apps
 */

import { Request, Response, NextFunction } from 'express';
import { getLogger } from '@kitiumai/logger';
import {
  isAuthError,
  formatErrorResponse,
  getStatusCode,
  toAuthError,
  NotFoundError,
} from '../errors';
import { logError, problemDetailsFrom } from '@kitiumai/error';

const logger = getLogger();

/**
 * Global error handler middleware
 */
export function errorHandler(
  error: unknown,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const kitiumError = toAuthError(error);
  const statusCode = getStatusCode(kitiumError);

  // Log error using @kitiumai/error logging
  logError(kitiumError);

  // Use Problem Details format (RFC 7807)
  const problem = problemDetailsFrom(kitiumError);

  // Enrich with request context
  const enrichedProblem = {
    ...problem,
    instance: req.path,
    extensions: {
      ...problem.extensions,
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
    },
  };

  logger.error('Request error', {
    statusCode,
    path: req.path,
    method: req.method,
    error: kitiumError.code,
    message: kitiumError.message,
  });

  res.status(statusCode).json(enrichedProblem);
}

/**
 * Async handler wrapper for route handlers
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
) {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Setup error handling for Express app
 */
export function setupErrorHandling(app: any): void {
  // 404 handler
  app.use((req: Request, res: Response) => {
    const notFoundError = new NotFoundError({
      code: 'auth/route_not_found',
      message: 'Route not found',
      context: { path: req.path, method: req.method },
    });
    const problem = problemDetailsFrom(notFoundError);
    res.status(404).json({
      ...problem,
      instance: req.path,
    });
  });

  // Global error handler (must be last)
  app.use(errorHandler);

  logger.info('Error handling configured');
}
