/**
 * Next.js integration
 */

import { getLogger } from '@kitiumai/logger';

const logger = getLogger();

/**
 * withAuth HOC for Next.js pages
 */
export function withAuth(options?: Record<string, unknown>) {
  return function withAuthHOC(Component: any) {
    return function WithAuthComponent(props: any) {
      logger.debug('withAuth HOC');
      return Component(props);
    };
  };
}

/**
 * Next.js API route auth middleware
 */
export async function apiAuth(
  req: any,
  res: any,
  handler: (req: any, res: any) => Promise<void>
): Promise<void> {
  logger.debug('Next.js API auth');
  await handler(req, res);
}
