/**
 * Authentication and Authorization Errors
 * Re-exports and wrappers using @kitiumai/error
 */

import {
  KitiumError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  BusinessError,
  InternalError,
  toKitiumError,
  problemDetailsFrom,
} from '@kitiumai/error';

/**
 * Base authentication error class
 * Extends KitiumError for consistency
 */
export class AuthError extends KitiumError {
  constructor(
    message: string,
    code: string = 'auth/error',
    statusCode: number = 400,
    details?: Record<string, unknown>
  ) {
    super({
      code,
      message,
      statusCode,
      severity: 'error',
      kind: 'internal',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'AuthError';
  }
}

// Re-export typed error classes from @kitiumai/error
export { ValidationError } from '@kitiumai/error';
export { AuthenticationError } from '@kitiumai/error';
export { AuthorizationError } from '@kitiumai/error';
export { NotFoundError } from '@kitiumai/error';
export { ConflictError } from '@kitiumai/error';
export { RateLimitError } from '@kitiumai/error';
export { InternalError } from '@kitiumai/error';

/**
 * OAuth error
 */
export class OAuthError extends KitiumError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/oauth_error',
      message,
      statusCode: 400,
      severity: 'error',
      kind: 'auth',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'OAuthError';
  }
}

/**
 * Provider not found error
 */
export class ProviderNotFoundError extends NotFoundError {
  constructor(providerId: string) {
    super({
      code: 'auth/provider_not_found',
      message: `Provider not found: ${providerId}`,
      severity: 'warning',
      retryable: false,
      context: { providerId },
    });
    this.name = 'ProviderNotFoundError';
  }
}

/**
 * Token error
 */
export class TokenError extends AuthenticationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/token_error',
      message,
      severity: 'error',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'TokenError';
  }
}

/**
 * Session error
 */
export class SessionError extends AuthenticationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/session_error',
      message,
      severity: 'error',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'SessionError';
  }
}

/**
 * API key error
 */
export class ApiKeyError extends AuthenticationError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/api_key_error',
      message,
      severity: 'error',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'ApiKeyError';
  }
}

/**
 * Database error
 */
export class DatabaseError extends InternalError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/database_error',
      message,
      severity: 'error',
      retryable: true,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'DatabaseError';
  }
}

/**
 * Configuration error
 */
export class ConfigurationError extends InternalError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/config_error',
      message,
      severity: 'error',
      retryable: false,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'ConfigurationError';
  }
}

/**
 * Integration error
 */
export class IntegrationError extends InternalError {
  constructor(message: string, details?: Record<string, unknown>) {
    super({
      code: 'auth/integration_error',
      message,
      severity: 'error',
      retryable: true,
      ...(details ? { context: details as any } : {}),
    });
    this.name = 'IntegrationError';
  }
}

/**
 * Check if error is an AuthError or KitiumError
 */
export function isAuthError(error: unknown): error is AuthError | KitiumError {
  return error instanceof AuthError || error instanceof KitiumError;
}

/**
 * Convert any error to KitiumError
 */
export function toAuthError(error: unknown): KitiumError {
  if (error instanceof KitiumError) {
    return error;
  }

  if (error instanceof AuthError) {
    return error;
  }

  return toKitiumError(error, {
    code: 'auth/internal_error',
    message: error instanceof Error ? error.message : 'An unknown error occurred',
    statusCode: 500,
    severity: 'error',
    kind: 'internal',
    retryable: false,
    cause: error,
  });
}

/**
 * Get HTTP status code for error
 */
export function getStatusCode(error: unknown): number {
  if (error instanceof KitiumError) {
    return error.statusCode || 500;
  }
  return 500;
}

/**
 * Format error response for API
 * Uses Problem Details format from @kitiumai/error
 */
export function formatErrorResponse(error: unknown): {
  error: string;
  code: string;
  statusCode: number;
  details?: Record<string, unknown>;
} {
  const kitiumError = toAuthError(error);
  const problem = problemDetailsFrom(kitiumError);

  return {
    error: kitiumError.message,
    code: kitiumError.code,
    statusCode: problem.status || kitiumError.statusCode || 500,
    details: problem.extensions as Record<string, unknown>,
  };
}
