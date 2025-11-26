/* eslint-disable no-restricted-imports */
/**
 * Email authentication routes
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import type { AuthCore, SessionRecord, UserRecord } from '../core';
import { AuthenticationError, ValidationError } from '../errors';
import { EmailAuthService } from './service';
import { EmailVerificationManager, VerificationTokenRecord } from './verification';

export interface EmailRegistrationRequest {
  email: string;
  password: string;
}

export interface EmailLoginRequest {
  email: string;
  password: string;
}

export interface EmailResetRequest {
  email: string;
}

export interface EmailPasswordResetRequest {
  token: string;
  password: string;
}

export interface EmailMagicLinkRequest {
  email: string;
}

export interface EmailRouteControllerOptions {
  auth: AuthCore;
  emailService?: EmailAuthService;
  verificationManager?: EmailVerificationManager;
}

export interface EmailRouteController {
  register(
    payload: EmailRegistrationRequest
  ): Promise<{ user: UserRecord; verificationLink: string }>;
  login(payload: EmailLoginRequest): Promise<{ user: UserRecord; session: SessionRecord }>;
  requestPasswordReset(payload: EmailResetRequest): Promise<{ resetLink: string }>;
  resetPassword(payload: EmailPasswordResetRequest): Promise<{ email?: string }>;
  sendMagicLink(payload: EmailMagicLinkRequest): Promise<{ loginLink: string }>;
  verifyToken(token: string): Promise<VerificationTokenRecord>;
}

export interface CreateEmailRoutesOptions extends EmailRouteControllerOptions {
  basePath?: string;
}

export function createEmailRouteController(
  options: EmailRouteControllerOptions
): EmailRouteController {
  const auth = options.auth;
  const emailService = options.emailService ?? new EmailAuthService();
  const verificationManager = options.verificationManager ?? new EmailVerificationManager();

  return {
    async register(payload) {
      assertEmailPayload(payload);
      const user = await auth.createUser(payload.email, payload.password);
      const verificationLink = await verificationManager.generateVerificationLink(user.email, {
        userId: user.id,
      });
      await emailService.sendVerificationEmail(user.email, verificationLink);
      return { user, verificationLink };
    },

    async login(payload) {
      assertEmailPayload(payload);
      const user = await auth.authenticateUser(payload.email, payload.password);
      const session = await auth.createSession(user.id);
      return { user, session };
    },

    async requestPasswordReset(payload) {
      assertEmail(payload.email);
      const resetLink = await verificationManager.generateResetLink(payload.email);
      await emailService.sendPasswordResetEmail(payload.email, resetLink);
      return { resetLink };
    },

    async resetPassword(payload) {
      if (!payload.token || typeof payload.token !== 'string') {
        throw new ValidationError({
          code: 'auth/invalid_token',
          message: 'Reset token is required',
          severity: 'error',
          retryable: false,
        });
      }
      if (!payload.password || typeof payload.password !== 'string') {
        throw new ValidationError({
          code: 'auth/invalid_password',
          message: 'Password is required',
          severity: 'error',
          retryable: false,
        });
      }
      const tokenRecord = verificationManager.consumeToken(payload.token, 'reset');
      if (!tokenRecord) {
        throw new AuthenticationError({
          code: 'auth/invalid_reset_token',
          message: 'Reset token is invalid or expired',
          severity: 'error',
          retryable: false,
        });
      }

      return { email: tokenRecord.email };
    },

    async sendMagicLink(payload) {
      assertEmail(payload.email);
      const loginLink = await verificationManager.generateLoginLink(payload.email);
      await emailService.sendMagicLinkEmail(payload.email, loginLink);
      return { loginLink };
    },

    async verifyToken(token) {
      if (!token) {
        throw new ValidationError({
          code: 'auth/missing_token',
          message: 'Verification token is required',
          severity: 'error',
          retryable: false,
        });
      }

      const record = verificationManager.consumeToken(token, 'verify');
      if (!record) {
        throw new AuthenticationError({
          code: 'auth/invalid_verification_token',
          message: 'Verification token is invalid or expired',
          severity: 'error',
          retryable: false,
        });
      }

      return record;
    },
  };
}

export async function createEmailRoutes(options: CreateEmailRoutesOptions): Promise<Router> {
  const controller = createEmailRouteController(options);
  const router = Router();
  const basePath = options.basePath || '/auth/email';

  router.post(
    `${basePath}/register`,
    wrap(async (req, res) => {
      const result = await controller.register(req.body as EmailRegistrationRequest);
      res.status(201).json(result);
    })
  );

  router.post(
    `${basePath}/login`,
    wrap(async (req, res) => {
      const result = await controller.login(req.body as EmailLoginRequest);
      res.status(200).json(result);
    })
  );

  router.post(
    `${basePath}/forgot-password`,
    wrap(async (req, res) => {
      const result = await controller.requestPasswordReset(req.body as EmailResetRequest);
      res.status(200).json(result);
    })
  );

  router.post(
    `${basePath}/reset-password`,
    wrap(async (req, res) => {
      const result = await controller.resetPassword(req.body as EmailPasswordResetRequest);
      res.status(200).json(result);
    })
  );

  router.post(
    `${basePath}/magic-link`,
    wrap(async (req, res) => {
      const result = await controller.sendMagicLink(req.body as EmailMagicLinkRequest);
      res.status(200).json(result);
    })
  );

  router.get(
    `${basePath}/verify/:token`,
    wrap(async (req, res) => {
      const token = req.params['token'];
      if (!token) {
        res.status(400).json({ error: 'Verification token is required' });
        return;
      }
      const result = await controller.verifyToken(token);
      res.status(200).json({ verified: true, email: result.email });
    })
  );

  return router;
}

function wrap(handler: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    handler(req, res).catch(next);
  };
}

function assertEmailPayload(payload: EmailRegistrationRequest | EmailLoginRequest): void {
  assertEmail(payload.email);
  if (!payload.password || typeof payload.password !== 'string') {
    throw new ValidationError({
      code: 'auth/invalid_password',
      message: 'Password is required',
      severity: 'error',
      retryable: false,
    });
  }
}

function assertEmail(email: string | undefined): asserts email is string {
  if (!email || typeof email !== 'string') {
    throw new ValidationError({
      code: 'auth/invalid_email',
      message: 'Email is required',
      severity: 'error',
      retryable: false,
    });
  }
}
