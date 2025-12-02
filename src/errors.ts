/**
 * Authentication and Authorization Errors
 * Re-exports and wrappers using @kitiumai/error with ErrorRegistry pattern
 */

import {
  AuthenticationError as KitiumAuthenticationError,
  InternalError,
  KitiumError,
  problemDetailsFrom,
  ValidationError as KitiumValidationError,
} from '@kitiumai/error';

/**
 * Centralized authentication error definitions
 * Registered with ErrorRegistry for governance and consistency
 */
export const AUTH_ERRORS = {
  // Validation errors
  INVALID_CONFIGURATION: {
    kind: 'validation' as const,
    severity: 'error' as const,
    message: 'Invalid auth configuration',
    httpStatus: 400,
    retryable: false,
  },
  MISSING_ENV_VAR: {
    kind: 'validation' as const,
    severity: 'error' as const,
    message: 'Required environment variable is missing',
    httpStatus: 400,
    retryable: false,
  },
  INVALID_PASSWORD: {
    kind: 'validation' as const,
    severity: 'error' as const,
    message: 'Password does not meet strength requirements',
    httpStatus: 400,
    retryable: false,
  },
  INVALID_EMAIL: {
    kind: 'validation' as const,
    severity: 'error' as const,
    message: 'Invalid email address format',
    httpStatus: 400,
    retryable: false,
  },

  // Authentication errors
  INVALID_CREDENTIALS: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'Invalid authentication credentials',
    httpStatus: 401,
    retryable: false,
  },
  USER_NOT_FOUND: {
    kind: 'not_found' as const,
    severity: 'error' as const,
    message: 'User not found',
    httpStatus: 404,
    retryable: false,
  },
  INVALID_TOKEN: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'Invalid or expired token',
    httpStatus: 401,
    retryable: false,
  },
  SESSION_EXPIRED: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'Session has expired',
    httpStatus: 401,
    retryable: false,
  },
  INVALID_API_KEY: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'Invalid API key',
    httpStatus: 401,
    retryable: false,
  },
  API_KEY_EXPIRED: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'API key has expired',
    httpStatus: 401,
    retryable: false,
  },

  // Authorization errors
  UNAUTHORIZED: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'User is not authorized to perform this action',
    httpStatus: 403,
    retryable: false,
  },
  INSUFFICIENT_PERMISSIONS: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'Insufficient permissions for this operation',
    httpStatus: 403,
    retryable: false,
  },

  // OAuth errors
  OAUTH_ERROR: {
    kind: 'auth' as const,
    severity: 'error' as const,
    message: 'OAuth authentication failed',
    httpStatus: 401,
    retryable: false,
  },
  PROVIDER_NOT_FOUND: {
    kind: 'not_found' as const,
    severity: 'error' as const,
    message: 'OAuth provider not found',
    httpStatus: 404,
    retryable: false,
  },

  // Dependency errors
  DATABASE_ERROR: {
    kind: 'dependency' as const,
    severity: 'error' as const,
    message: 'Database operation failed',
    httpStatus: 503,
    retryable: true,
  },
  EMAIL_SEND_FAILED: {
    kind: 'dependency' as const,
    severity: 'error' as const,
    message: 'Failed to send email',
    httpStatus: 503,
    retryable: true,
  },
  INTEGRATION_ERROR: {
    kind: 'dependency' as const,
    severity: 'error' as const,
    message: 'Third-party integration error',
    httpStatus: 503,
    retryable: true,
  },

  // Internal errors
  INTERNAL_ERROR: {
    kind: 'internal' as const,
    severity: 'error' as const,
    message: 'An internal server error occurred',
    httpStatus: 500,
    retryable: false,
  },
  CONFIG_ERROR: {
    kind: 'internal' as const,
    severity: 'error' as const,
    message: 'Configuration error',
    httpStatus: 500,
    retryable: false,
  },

  // Rate limiting
  RATE_LIMIT_EXCEEDED: {
    kind: 'rate_limit' as const,
    severity: 'warning' as const,
    message: 'Rate limit exceeded',
    httpStatus: 429,
    retryable: true,
  },
} as const;

/**
 * Create an auth error using the appropriate error class based on error code
 * Maps error codes to suitable KitiumError subclasses for type safety
 */
export function createError(
  code: string,
  options: {
    message?: string;
    cause?: Error;
    context?: Record<string, unknown>;
  } = {}
): KitiumError {
  const errorDef = (AUTH_ERRORS as Record<string, unknown>)[code.split('/')[1] || ''];
  const errorDefEntry = errorDef as { message?: string; kind?: string } | undefined;

  // Select appropriate error class based on error code prefix or kind
  if (code.startsWith('auth/invalid') || code.includes('validation') || code.includes('email')) {
    return new KitiumValidationError({
      code,
      message: options.message || errorDefEntry?.message || 'Validation error',
      severity: 'warning',
      retryable: false,
      cause: options.cause,
      context: options.context,
    });
  }

  if (code.includes('credential') || code.includes('token') || code.includes('auth')) {
    return new KitiumAuthenticationError({
      code,
      message: options.message || errorDefEntry?.message || 'Authentication error',
      severity: 'error',
      retryable: false,
      cause: options.cause,
      context: options.context,
    });
  }

  // Default to InternalError for other codes
  return new InternalError({
    code,
    message: options.message || errorDefEntry?.message || 'An error occurred',
    severity: 'error',
    retryable: false,
    cause: options.cause,
    context: options.context,
  });
}

// Re-export typed error classes and utilities from @kitiumai/error
export {
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  InternalError,
  NotFoundError,
  problemDetailsFrom,
  RateLimitError,
  ValidationError,
} from '@kitiumai/error';

/**
 * Check if error is a KitiumError
 */
export function isAuthError(error: unknown): error is KitiumError {
  return error instanceof KitiumError;
}

/**
 * Convert any error to KitiumError
 * Wraps unknown errors with proper context
 */
export function toAuthError(error: unknown): KitiumError {
  if (error instanceof KitiumError) {
    return error;
  }

  return new InternalError({
    code: 'auth/internal_error',
    message: error instanceof Error ? error.message : 'An unknown error occurred',
    severity: 'error',
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
