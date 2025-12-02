/**
 * Email authentication service
 * Uses Result types for error handling and branded types for type safety
 */

import { getLogger } from '@kitiumai/logger';
import { err, ok } from '@kitiumai/utils-ts/runtime/result';

import { createError } from '../errors';
import { type EmailProvider, MockEmailProvider } from './providers';
import {
  createEmailVerificationTemplate,
  createLoginLinkTemplate,
  createPasswordResetTemplate,
} from './templates';
import type { Result } from '@kitiumai/utils-ts/types/result';

export type EmailAuthServiceOptions = {
  provider?: EmailProvider;
  from?: string;
};

export class EmailAuthService {
  private readonly provider: EmailProvider;
  private readonly logger = getLogger();

  constructor(options: EmailAuthServiceOptions = {}) {
    this.provider = options.provider ?? new MockEmailProvider();
    this.logger.debug('EmailAuthService initialized');
  }

  /**
   * Send email verification link
   * Returns Result type for error handling
   */
  async sendVerificationEmail(email: string, link: string): Promise<Result<void>> {
    try {
      this.logger.debug('Sending verification email', { email });

      if (!email || !link) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: 'Email and link are required' },
          })
        );
      }

      const template = createEmailVerificationTemplate(link);
      await this.provider.send(email, 'Verify your email address', template);

      this.logger.info('Verification email sent', { email });
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to send verification email', { error: String(error), email });
      return err(
        createError('auth/email_send_failed', {
          cause: error as Error,
          context: { email, type: 'verification' },
        })
      );
    }
  }

  /**
   * Send password reset email
   * Returns Result type for error handling
   */
  async sendPasswordResetEmail(email: string, link: string): Promise<Result<void>> {
    try {
      this.logger.debug('Sending password reset email', { email });

      if (!email || !link) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: 'Email and link are required' },
          })
        );
      }

      const template = createPasswordResetTemplate(link);
      await this.provider.send(email, 'Reset your password', template);

      this.logger.info('Password reset email sent', { email });
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to send password reset email', { error: String(error), email });
      return err(
        createError('auth/email_send_failed', {
          cause: error as Error,
          context: { email, type: 'password_reset' },
        })
      );
    }
  }

  /**
   * Send magic link email for passwordless auth
   * Returns Result type for error handling
   */
  async sendMagicLinkEmail(email: string, link: string): Promise<Result<void>> {
    try {
      this.logger.debug('Sending magic link email', { email });

      if (!email || !link) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: 'Email and link are required' },
          })
        );
      }

      const template = createLoginLinkTemplate(link);
      await this.provider.send(email, 'Your sign-in link', template);

      this.logger.info('Magic link email sent', { email });
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to send magic link email', { error: String(error), email });
      return err(
        createError('auth/email_send_failed', {
          cause: error as Error,
          context: { email, type: 'magic_link' },
        })
      );
    }
  }

  /**
   * Send custom email with template
   * Returns Result type for error handling
   */
  async sendEmail(email: string, subject: string, html: string): Promise<Result<void>> {
    try {
      this.logger.debug('Sending custom email', { email, subject });

      if (!email || !subject || !html) {
        return err(
          createError('auth/invalid_credentials', {
            context: { reason: 'Email, subject, and html are required' },
          })
        );
      }

      await this.provider.send(email, subject, html);

      this.logger.info('Custom email sent', { email, subject });
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to send custom email', { error: String(error), email });
      return err(
        createError('auth/email_send_failed', {
          cause: error as Error,
          context: { email },
        })
      );
    }
  }
}

