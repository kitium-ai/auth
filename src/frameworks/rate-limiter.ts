/**
 * Rate limiting
 * Track and limit request rates
 */

import { RateLimitError } from '../errors';

/**
 * Rate limit store entry
 */
type RateLimitEntry = {
  count: number;
  resetAt: number;
};

/**
 * Rate limiter
 */
export class RateLimiter {
  private readonly store = new Map<string, RateLimitEntry>();

  constructor(
    private readonly maxRequests = 100,
    private readonly windowMs = 60000 // 1 minute
  ) {}

  /**
   * Check if request is allowed
   */
  isAllowed(key: string): boolean {
    const now = Date.now();
    const entry = this.store.get(key);

    if (!entry || now > entry.resetAt) {
      // Reset or create new entry
      this.store.set(key, {
        count: 1,
        resetAt: now + this.windowMs,
      });
      return true;
    }

    if (entry.count < this.maxRequests) {
      entry.count++;
      return true;
    }

    return false;
  }

  /**
   * Get current count for key
   */
  getCount(key: string): number {
    const entry = this.store.get(key);
    if (!entry || Date.now() > entry.resetAt) {
      return 0;
    }
    return entry.count;
  }

  /**
   * Get reset time for key
   */
  getResetTime(key: string): Date | null {
    const entry = this.store.get(key);
    if (!entry) {
      return null;
    }
    return new Date(entry.resetAt);
  }

  /**
   * Reset key
   */
  reset(key: string): void {
    this.store.delete(key);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.store.clear();
  }

  /**
   * Enforce rate limit and throw when exceeded
   */
  enforce(key: string): void {
    if (!this.isAllowed(key)) {
      throw new RateLimitError({
        code: 'auth/rate_limit_exceeded',
        message: 'Rate limit exceeded',
        severity: 'error',
        retryable: false,
      });
    }
  }
}

/**
 * Generate rate limit key
 */
export function generateRateLimitKey(type: string, identifier: string): string {
  return `${type}:${identifier}`;
}

/**
 * Generate rate limit headers
 */
export function generateRateLimitHeaders(
  limiter: RateLimiter,
  key: string,
  maxRequests: number
): Record<string, string> {
  const count = limiter.getCount(key);
  const resetTime = limiter.getResetTime(key);

  return {
    'RateLimit-Limit': String(maxRequests),
    'RateLimit-Remaining': String(Math.max(0, maxRequests - count)),
    'RateLimit-Reset': resetTime?.toISOString() || new Date().toISOString(),
  };
}
