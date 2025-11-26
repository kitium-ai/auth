/**
 * Hooks and Events System
 * Event-driven extensibility for authentication flows
 */

import { UserRecord, SessionRecord, ApiKeyRecord, OrganizationRecord } from '../types';

/**
 * Hook event types
 */
export type HookEventType =
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'user.email.verified'
  | 'user.password.changed'
  | 'session.created'
  | 'session.updated'
  | 'session.deleted'
  | 'session.expired'
  | 'auth.login'
  | 'auth.logout'
  | 'auth.login.failed'
  | 'auth.password.reset'
  | 'auth.email.verification.sent'
  | 'api_key.created'
  | 'api_key.revoked'
  | 'api_key.used'
  | 'organization.created'
  | 'organization.updated'
  | 'organization.deleted'
  | 'organization.member.added'
  | 'organization.member.removed'
  | 'role.assigned'
  | 'role.revoked'
  | '2fa.enabled'
  | '2fa.disabled'
  | '2fa.verified'
  | 'oauth.linked'
  | 'oauth.unlinked'
  | 'sso.login'
  | 'sso.login.failed';

/**
 * Hook context with event data
 */
export interface HookContext {
  event: HookEventType;
  timestamp: Date;
  userId?: string;
  orgId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

/**
 * User-related hook data
 */
export interface UserHookData {
  user: UserRecord;
  previousUser?: UserRecord;
}

/**
 * Session-related hook data
 */
export interface SessionHookData {
  session: SessionRecord;
  previousSession?: SessionRecord;
}

/**
 * API key-related hook data
 */
export interface ApiKeyHookData {
  apiKey: ApiKeyRecord;
  previousApiKey?: ApiKeyRecord;
}

/**
 * Organization-related hook data
 */
export interface OrganizationHookData {
  organization: OrganizationRecord;
  previousOrganization?: OrganizationRecord;
  memberId?: string;
  roleId?: string;
}

/**
 * Authentication-related hook data
 */
export interface AuthHookData {
  userId: string;
  email?: string;
  provider?: string;
  success: boolean;
  reason?: string;
}

/**
 * Hook handler function type
 */
export type HookHandler<T = unknown> = (context: HookContext, data: T) => Promise<void> | void;

/**
 * Hook registration
 */
export interface HookRegistration {
  id: string;
  event: HookEventType;
  handler: HookHandler;
  priority?: number; // Lower numbers execute first
  enabled?: boolean;
}

/**
 * Hook manager interface
 */
export interface HookManager {
  /**
   * Register a hook handler
   */
  on<T = unknown>(event: HookEventType, handler: HookHandler<T>, priority?: number): string;

  /**
   * Register a one-time hook handler
   */
  once<T = unknown>(event: HookEventType, handler: HookHandler<T>, priority?: number): string;

  /**
   * Unregister a hook handler
   */
  off(hookId: string): void;

  /**
   * Emit a hook event
   */
  emit<T = unknown>(event: HookEventType, context: HookContext, data: T): Promise<void>;

  /**
   * Get all registered hooks for an event
   */
  getHooks(event: HookEventType): HookRegistration[];

  /**
   * Clear all hooks for an event
   */
  clear(event?: HookEventType): void;
}
