/**
 * Password handling utilities
 * Secure password hashing, validation, and token generation
 */

import * as crypto from 'crypto';
import { isEmail } from '@kitiumai/utils-ts';

/**
 * Password hashing options
 */
export interface PasswordHashOptions {
  iterations?: number;
  keyLength?: number;
  digest?: string;
}

/**
 * Password validation rules
 */
export interface PasswordValidationRules {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
}

/**
 * Hash a password using PBKDF2
 */
export function hashPassword(
  password: string,
  salt?: string,
  options: PasswordHashOptions = {}
): string {
  const { iterations = 100000, keyLength = 64, digest = 'sha256' } = options;
  const passwordSalt = salt || crypto.randomBytes(16).toString('hex');

  const hash = crypto
    .pbkdf2Sync(password, passwordSalt, iterations, keyLength, digest)
    .toString('hex');

  return `${passwordSalt}:${hash}`;
}

/**
 * Verify a password against a hash
 */
export function verifyPassword(password: string, hash: string): boolean {
  try {
    const parts = hash.split(':');
    const salt = parts[0];
    const storedHash = parts[1];
    if (!salt || !storedHash) {
      return false;
    }

    const newHash = hashPassword(password, salt);
    const newParts = newHash.split(':');
    const newHashValue = newParts[1];
    if (!newHashValue) {
      return false;
    }

    // Constant time comparison
    return crypto.timingSafeEqual(Buffer.from(storedHash), Buffer.from(newHashValue));
  } catch {
    return false;
  }
}

/**
 * Validate password strength
 */
export function validatePasswordStrength(
  password: string,
  rules: PasswordValidationRules = {}
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const {
    minLength = 8,
    maxLength = 128,
    requireUppercase = true,
    requireLowercase = true,
    requireNumbers = true,
    requireSpecialChars = true,
  } = rules;

  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters long`);
  }

  if (password.length > maxLength) {
    errors.push(`Password must not exceed ${maxLength} characters`);
  }

  if (requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (requireSpecialChars && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Generate a password reset token
 */
export function generatePasswordResetToken(
  userId: string,
  expiresInMinutes: number = 30
): { token: string; expiresAt: Date } {
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const tokenData = `${userId}:${randomBytes}`;
  const token = Buffer.from(tokenData).toString('base64');

  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + expiresInMinutes);

  return { token, expiresAt };
}

/**
 * Validate email format
 */
export function validateEmail(email: string): boolean {
  return isEmail(email);
}

/**
 * Normalize email (lowercase and trim)
 */
export function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}
