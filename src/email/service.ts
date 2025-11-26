/**
 * Email authentication service
 */

import { getLogger } from '@kitiumai/logger';

const logger = getLogger();

export class EmailAuthService {
  async sendVerificationEmail(email: string): Promise<void> {
    logger.debug('Sending verification email', { email });
  }

  async sendPasswordResetEmail(email: string): Promise<void> {
    logger.debug('Sending password reset email', { email });
  }
}
