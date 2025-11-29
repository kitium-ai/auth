/**
 * Authentication utility functions
 * API key generation, hashing, and verification
 */

import * as crypto from 'crypto';
import { createLogger } from '@kitiumai/logger';

const logger = createLogger();

/**
 * Generate a random API key
 */
export function generateApiKey(prefix: string = 'api'): string {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  return `${prefix}_${randomBytes}`;
}

/**
 * Hash an API key for storage
 */
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/**
 * Verify an API key against a hash
 */
export function verifyApiKey(apiKey: string, hash: string): boolean {
  try {
    const keyHash = hashApiKey(apiKey);
    // Constant time comparison
    return crypto.timingSafeEqual(Buffer.from(keyHash), Buffer.from(hash));
  } catch (error) {
    logger.debug('API key verification failed', { error: String(error) });
    return false;
  }
}
