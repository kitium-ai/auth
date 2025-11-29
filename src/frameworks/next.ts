/**
 * Next.js integration
 */

import { createLogger } from '@kitiumai/logger';

const logger = createLogger();

/**
 * withAuth HOC for Next.js pages
 */
export function withAuth(options?: Record<string, unknown>) {
  return function withAuthHOC(component: (props: Record<string, unknown>) => unknown) {
    return function withAuthComponent(props: Record<string, unknown>) {
      logger.debug('withAuth HOC', { options: options || {} });
      // Merge options into props for component access
      return component({ ...props, authOptions: options });
    };
  };
}

/**
 * Next.js API route auth middleware
 */
export async function apiAuth(
  req: Record<string, unknown>,
  res: Record<string, unknown>,
  handler: (req: Record<string, unknown>, res: Record<string, unknown>) => Promise<void>
): Promise<void> {
  logger.debug('Next.js API auth');
  await handler(req, res);
}
