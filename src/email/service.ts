/**
 * Email authentication service
 */

import { createLogger } from '@kitiumai/logger';
import { MockEmailProvider, type EmailProvider } from './providers';
import {
  createEmailVerificationTemplate,
  createPasswordResetTemplate,
  createLoginLinkTemplate,
} from './templates';

const logger = createLogger();

export interface EmailAuthServiceOptions {
  provider?: EmailProvider;
  from?: string;
}

export class EmailAuthService {
  private readonly provider: EmailProvider;

  constructor(options: EmailAuthServiceOptions = {}) {
    this.provider = options.provider ?? new MockEmailProvider();
  }

  async sendVerificationEmail(email: string, link: string): Promise<void> {
    logger.debug('Sending verification email', { email });
    await this.provider.send(
      email,
      'Verify your email address',
      createEmailVerificationTemplate(link)
    );
  }

  async sendPasswordResetEmail(email: string, link: string): Promise<void> {
    logger.debug('Sending password reset email', { email });
    await this.provider.send(email, 'Reset your password', createPasswordResetTemplate(link));
  }

  async sendMagicLinkEmail(email: string, link: string): Promise<void> {
    logger.debug('Sending magic link email', { email });
    await this.provider.send(email, 'Your sign-in link', createLoginLinkTemplate(link));
  }
}
