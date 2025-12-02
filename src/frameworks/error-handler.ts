/**
 * Error handling middleware
 * Global error handling for Express apps
 */

import { logError, problemDetailsFrom } from '@kitiumai/error';
import { createLogger } from '@kitiumai/logger';
import type { NextFunction, Request, Response } from 'express';

import { getStatusCode, NotFoundError, toAuthError } from '../errors';

const logger = createLogger();

/**
 * Global error handler middleware
 */
export function errorHandler(
  error: unknown,
  request: Request,
  res: Response,
  _next: NextFunction
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
    instance: request.path,
    extensions: {
      ...problem.extensions,
      path: request.path,
      method: request.method,
      timestamp: new Date().toISOString(),
    },
  };

  logger.error('Request error', {
    statusCode,
    path: request.path,
    method: request.method,
    error: kitiumError.code,
    message: kitiumError.message,
  });

  res.status(statusCode).json(enrichedProblem);
}

/**
 * Async handler wrapper for route handlers
 */
export function asyncHandler(
  function_: (request: Request, res: Response, next: NextFunction) => Promise<unknown>
): (request: Request, res: Response, next: NextFunction) => void {
  return (request: Request, res: Response, next: NextFunction) => {
    Promise.resolve(function_(request, res, next)).catch(next);
  };
}

/**
 * Setup error handling for Express app
 */
export function setupErrorHandling(app: { use: (handler: unknown) => void }): void {
  // 404 handler
  app.use((request: Request, res: Response) => {
    const notFoundError = new NotFoundError({
      code: 'auth/route_not_found',
      message: 'Route not found',
      severity: 'error',
      retryable: false,
      context: { path: request.path, method: request.method },
    });
    const problem = problemDetailsFrom(notFoundError);
    res.status(404).json({
      ...problem,
      instance: request.path,
    });
  });

  // Global error handler (must be last)
  app.use(errorHandler);

  logger.info('Error handling configured');
}
