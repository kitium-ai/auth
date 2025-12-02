import { createLogger } from '@kitiumai/logger';
import type { NextFunction, Request, Response } from 'express';

import { AuthorizationError } from '../errors';
import type { RBACService } from '../rbac/service';

/**
 * RBAC Middleware for Express.js
 * Enforces role-based access control on routes
 */

export type RBACMiddlewareOptions = {
  rbacService: RBACService;
  orgIdExtractor?: (request: Request) => string | undefined;
};

/**
 * Require specific role for route access
 */
export function requireRole(
  roleNames: string[],
  options: RBACMiddlewareOptions
): (request: Request, res: Response, next: NextFunction) => Promise<void> {
  const logger = createLogger();
  return async (request: Request, res: Response, next: NextFunction) => {
    try {
      const user = (request as { user?: { id: string; orgId?: string } }).user;
      if (!user?.id) {
        logger.warn('Role check attempted but user not authenticated', { roles: roleNames });
        throw new AuthorizationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'warning',
          retryable: false,
        });
      }

      const orgId = options.orgIdExtractor?.(request) || user.orgId;
      if (!orgId) {
        throw new AuthorizationError({
          code: 'auth/org_not_found',
          message: 'Organization not found in request context',
          severity: 'warning',
          retryable: false,
        });
      }

      const userRoles = await options.rbacService.getUserRoles(user.id, orgId);
      const hasRequiredRole = userRoles.some((role) => roleNames.includes(role.name));

      if (!hasRequiredRole) {
        throw new AuthorizationError({
          code: 'auth/insufficient_roles',
          message: `Required roles: ${roleNames.join(', ')}`,
          severity: 'warning',
          retryable: false,
          context: { requiredRoles: roleNames },
        });
      }

      next();
    } catch {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
}

/**
 * Require specific permission for route access
 */
export function requirePermission(
  resource: string,
  action: string,
  options: RBACMiddlewareOptions
): (request: Request, res: Response, next: NextFunction) => Promise<void> {
  const logger = createLogger();
  return async (request: Request, res: Response, next: NextFunction) => {
    try {
      const user = (request as { user?: { id: string; orgId?: string } }).user;
      if (!user?.id) {
        logger.warn('Permission check attempted but user not authenticated', { resource, action });
        throw new AuthorizationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'warning',
          retryable: false,
        });
      }

      logger.debug('Checking permission', { userId: user.id, resource, action });

      const orgId = options.orgIdExtractor?.(request) || user.orgId;

      const hasPermission = await options.rbacService.hasPermission(user.id, {
        resource,
        action,
        orgId,
      });

      if (!hasPermission) {
        throw new AuthorizationError({
          code: 'auth/insufficient_permissions',
          message: `Required permission: ${resource}:${action}`,
          severity: 'warning',
          retryable: false,
          context: { resource, action },
        });
      }

      next();
    } catch {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
}

/**
 * Require any of the specified permissions
 */
export function requireAnyPermission(
  checks: Array<{ resource: string; action: string }>,
  options: RBACMiddlewareOptions
): (request: Request, res: Response, next: NextFunction) => Promise<void> {
  return async (request: Request, res: Response, next: NextFunction) => {
    try {
      const user = (request as { user?: { id: string; orgId?: string } }).user;
      if (!user?.id) {
        throw new AuthorizationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'warning',
          retryable: false,
        });
      }

      const orgId = options.orgIdExtractor?.(request) || user.orgId;

      const hasPermission = await options.rbacService.hasAnyPermission(
        user.id,
        checks.map((c) => ({ ...c, orgId }))
      );

      if (!hasPermission) {
        throw new AuthorizationError({
          code: 'auth/required_permissions_not_found',
          message: 'Required permissions not found',
          severity: 'warning',
          retryable: false,
        });
      }

      next();
    } catch {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
}

/**
 * Require all of the specified permissions
 */
export function requireAllPermissions(
  checks: Array<{ resource: string; action: string }>,
  options: RBACMiddlewareOptions
): (request: Request, res: Response, next: NextFunction) => Promise<void> {
  return async (request: Request, res: Response, next: NextFunction) => {
    try {
      const user = (request as { user?: { id: string; orgId?: string } }).user;
      if (!user?.id) {
        throw new AuthorizationError({
          code: 'auth/user_not_authenticated',
          message: 'User not authenticated',
          severity: 'warning',
          retryable: false,
        });
      }

      const orgId = options.orgIdExtractor?.(request) || user.orgId;

      const hasPermission = await options.rbacService.hasAllPermissions(
        user.id,
        checks.map((c) => ({ ...c, orgId }))
      );

      if (!hasPermission) {
        throw new AuthorizationError({
          code: 'auth/not_all_permissions_found',
          message: 'Not all required permissions found',
          severity: 'warning',
          retryable: false,
        });
      }

      next();
    } catch {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
}

/**
 * Attach user roles and permissions to request
 */
export function enrichUserContext(
  options: RBACMiddlewareOptions
): (request: Request, res: Response, next: NextFunction) => Promise<void> {
  return async (request: Request, res: Response, next: NextFunction) => {
    try {
      const user = (request as { user?: { id: string; orgId?: string } }).user;
      if (!user?.id) {
        return next();
      }

      const orgId = options.orgIdExtractor?.(request) || user.orgId;
      if (!orgId) {
        return next();
      }

      const roles = await options.rbacService.getUserRoles(user.id, orgId);
      const permissions = await options.rbacService.getUserPermissions(user.id, orgId);

      const enrichedUser = {
        ...user,
        roles,
        permissions,
      };
      (
        request as {
          user?: { id: string; orgId?: string; roles?: unknown[]; permissions?: unknown[] };
        }
      ).user = enrichedUser;

      next();
    } catch {
      res.status(403).json({ error: 'Forbidden' });
    }
  };
}
