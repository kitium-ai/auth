/**
 * Next.js integration
 */

import { getLogger } from '@kitiumai/logger';
import { err } from '@kitiumai/utils-ts/runtime/result';

import { InternalError } from '../errors';
import type { Result } from '@kitiumai/utils-ts/types/result';

const logger = getLogger();

/**
 * Next.js API request type
 */
export type NextApiRequest = {
  method?: string;
  headers?: Record<string, string | string[]>;
  cookies?: Record<string, string>;
} & Record<string, unknown>;

/**
 * Next.js API response type
 */
export type NextApiResponse = {
  statusCode?: number;
} & Record<string, unknown>;

/**
 * withAuth HOC for Next.js pages
 */
export function withAuth(options?: Record<string, unknown>) {
  return function withAuthHOC(
    component: (props: Record<string, unknown>) => unknown
  ): (props: Record<string, unknown>) => unknown {
    return function withAuthComponent(props: Record<string, unknown>): unknown {
      try {
        logger.debug('withAuth HOC', { options: options || {} });
        // Merge options into props for component access
        return component({ ...props, authOptions: options });
      } catch (error) {
        logger.error('Error in withAuth HOC', { error: String(error) });
        throw error;
      }
    };
  };
}

/**
 * Next.js API route auth middleware
 */
export async function apiAuth(
  request: NextApiRequest,
  res: NextApiResponse,
  handler: (request_: NextApiRequest, res: NextApiResponse) => Promise<Result<void>>
): Promise<Result<void>> {
  try {
    logger.debug('Next.js API auth', { method: request.method });

    // Attach auth context to request
    request['auth'] = {};

    const result = await handler(request, res);
    return result;
  } catch (error) {
    logger.error('API auth middleware error', {
      error: String(error),
      method: request.method,
    });
    return err(
      new InternalError({
        code: 'auth/api_middleware_error',
        message: 'API middleware error',
        severity: 'error',
        retryable: false,
        cause: error as Error,
        context: { method: request.method as string },
      })
    );
  }
}

/**
 * Next.js API route wrapper with auth error handling
 */
export function withApiAuth(
  handler: (request: NextApiRequest, res: NextApiResponse) => Promise<Result<void>>
): (request: NextApiRequest, res: NextApiResponse) => Promise<void> {
  return async (request: NextApiRequest, res: NextApiResponse): Promise<void> => {
    try {
      const result = await apiAuth(request, res, handler);

      if (!result.ok) {
        res.statusCode = 401;
        const errorData = result.error as { code?: string; message?: string };
        return (res as { json?: (data: unknown) => void }).json?.({
          error: errorData.code || 'auth/unauthorized',
          message: errorData.message || 'Unauthorized',
        });
      }

      return;
    } catch (error) {
      logger.error('Unhandled error in API route', { error: String(error) });
      res.statusCode = 500;
      return (res as { json?: (data: unknown) => void }).json?.({
        error: 'auth/internal_error',
        message: 'An unexpected error occurred',
      });
    }
  };
}
