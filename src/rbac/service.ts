import { getLogger } from '@kitiumai/logger';
import type { OrganizationId, UserId } from '@kitiumai/types';
import { err, ok } from '@kitiumai/utils-ts/runtime/result';
import type { Result } from '@kitiumai/utils-ts/types/result';
import { nanoid } from 'nanoid';

import { createError } from '../errors';
import type {
  Permission,
  PermissionCheck,
  RBACConfig,
  Role,
  RoleRecord,
  StorageAdapter,
} from '../types';

/**
 * RBAC (Role-Based Access Control) Service
 * Manages roles, permissions, and role assignments with Result types
 */
export class RBACService {
  private readonly storage: StorageAdapter;
  private readonly config: RBACConfig;
  private readonly logger = getLogger();

  constructor(storage: StorageAdapter, config: RBACConfig = { enabled: false }) {
    this.storage = storage;
    this.config = config;
    this.logger.debug('RBACService initialized', { enabled: config.enabled });
  }

  /**
   * Create a new role with permissions
   */
  async createRole(
    orgId: OrganizationId,
    name: string,
    permissions: Permission[],
    description?: string
  ): Promise<Result<Role>> {
    if (!this.config.enabled) {
      this.logger.warn('Role creation attempted when RBAC disabled', { orgId });
      return err(
        createError('auth/rbac_not_enabled', {
          context: { orgId },
        })
      );
    }

    if (!name || name.trim().length === 0) {
      this.logger.warn('Role creation attempted with invalid name', { orgId });
      return err(
        createError('auth/role_name_required', {
          context: { orgId },
        })
      );
    }

    this.logger.debug('Creating new role', {
      orgId,
      roleName: name,
      permissionCount: permissions.length,
    });

    const roleId = `role_${nanoid()}`;
    const role: RoleRecord = {
      id: roleId,
      orgId,
      name,
      description,
      permissions,
      isSystem: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    if (!this.storage.createRole) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'createRole' },
        })
      );
    }

    try {
      const createdRole = await this.storage.createRole(role);
      return ok(createdRole);
    } catch (error) {
      this.logger.error('Failed to create role', { error: String(error), orgId, name });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'createRole', orgId, name },
        })
      );
    }
  }

  /**
   * Get a role by ID
   */
  async getRole(roleId: string): Promise<Result<Role | null>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { roleId },
        })
      );
    }

    if (!this.storage.getRole) {
      return ok(null);
    }

    try {
      const role = await this.storage.getRole(roleId);
      return ok(role);
    } catch (error) {
      this.logger.error('Failed to get role', { error: String(error), roleId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'getRole', roleId },
        })
      );
    }
  }

  /**
   * List all roles in an organization
   */
  async listRoles(orgId: OrganizationId): Promise<Result<Role[]>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { orgId },
        })
      );
    }

    if (!this.storage.listRoles) {
      return ok([]);
    }

    try {
      const roles = await this.storage.listRoles(orgId);
      return ok(roles);
    } catch (error) {
      this.logger.error('Failed to list roles', { error: String(error), orgId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'listRoles', orgId },
        })
      );
    }
  }

  /**
   * Update a role
   */
  async updateRole(roleId: string, updates: Partial<Role>): Promise<Result<Role>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { roleId },
        })
      );
    }

    const roleResult = await this.getRole(roleId);
    if (!roleResult.ok) {
      return roleResult;
    }

    if (!roleResult.value) {
      return err(
        createError('auth/role_not_found', {
          context: { roleId },
        })
      );
    }

    if (roleResult.value.isSystem) {
      return err(
        createError('auth/system_role_immutable', {
          context: { roleId },
        })
      );
    }

    if (!this.storage.updateRole) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'updateRole' },
        })
      );
    }

    try {
      const updatedRole = await this.storage.updateRole(roleId, {
        ...updates,
        updatedAt: new Date(),
      });
      return ok(updatedRole);
    } catch (error) {
      this.logger.error('Failed to update role', { error: String(error), roleId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'updateRole', roleId },
        })
      );
    }
  }

  /**
   * Delete a role
   */
  async deleteRole(roleId: string): Promise<Result<void>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { roleId },
        })
      );
    }

    const roleResult = await this.getRole(roleId);
    if (!roleResult.ok) {
      return roleResult;
    }

    if (!roleResult.value) {
      return err(
        createError('auth/role_not_found', {
          context: { roleId },
        })
      );
    }

    if (roleResult.value.isSystem) {
      return err(
        createError('auth/system_role_immutable', {
          context: { roleId },
        })
      );
    }

    if (!this.storage.deleteRole) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'deleteRole' },
        })
      );
    }

    try {
      await this.storage.deleteRole(roleId);
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to delete role', { error: String(error), roleId });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'deleteRole', roleId },
        })
      );
    }
  }

  /**
   * Assign a role to a user
   */
  async assignRoleToUser(
    userId: UserId,
    roleId: string,
    orgId: OrganizationId
  ): Promise<Result<void>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { userId, orgId },
        })
      );
    }

    const roleResult = await this.getRole(roleId);
    if (!roleResult.ok) {
      return roleResult;
    }

    if (!roleResult.value) {
      return err(
        createError('auth/role_not_found', {
          context: { roleId },
        })
      );
    }

    if (roleResult.value.orgId !== orgId) {
      return err(
        createError('auth/role_org_mismatch', {
          context: { roleId, orgId },
        })
      );
    }

    if (!this.storage.assignRoleToUser) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'assignRoleToUser' },
        })
      );
    }

    try {
      await this.storage.assignRoleToUser(userId, roleId, orgId);
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to assign role to user', {
        error: String(error),
        userId,
        roleId,
        orgId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'assignRoleToUser', userId, roleId, orgId },
        })
      );
    }
  }

  /**
   * Revoke a role from a user
   */
  async revokeRoleFromUser(
    userId: UserId,
    roleId: string,
    orgId: OrganizationId
  ): Promise<Result<void>> {
    if (!this.config.enabled) {
      return err(
        createError('auth/rbac_not_enabled', {
          context: { userId, orgId },
        })
      );
    }

    if (!this.storage.revokeRoleFromUser) {
      return err(
        createError('auth/storage_adapter_not_supported', {
          context: { operation: 'revokeRoleFromUser' },
        })
      );
    }

    try {
      await this.storage.revokeRoleFromUser(userId, roleId, orgId);
      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to revoke role from user', {
        error: String(error),
        userId,
        roleId,
        orgId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'revokeRoleFromUser', userId, roleId, orgId },
        })
      );
    }
  }

  /**
   * Get all roles assigned to a user in an organization
   */
  async getUserRoles(userId: UserId, orgId: OrganizationId): Promise<Result<Role[]>> {
    if (!this.config.enabled) {
      return ok([]);
    }

    if (!this.storage.getUserRoles) {
      return ok([]);
    }

    try {
      const roles = await this.storage.getUserRoles(userId, orgId);
      return ok(roles);
    } catch (error) {
      this.logger.error('Failed to get user roles', {
        error: String(error),
        userId,
        orgId,
      });
      return err(
        createError('auth/database_error', {
          cause: error as Error,
          context: { operation: 'getUserRoles', userId, orgId },
        })
      );
    }
  }

  /**
   * Check if a user has a specific permission
   */
  async hasPermission(userId: UserId, check: PermissionCheck): Promise<boolean> {
    if (!this.config.enabled) {
      return true; // RBAC disabled, allow all
    }

    const rolesResult = await this.getUserRoles(userId, (check.orgId || '') as OrganizationId);
    if (!rolesResult.ok) {
      this.logger.warn('Failed to check permission', {
        userId,
        resource: check.resource,
        action: check.action,
      });
      return false;
    }

    const userRoles = rolesResult.value;
    for (const role of userRoles) {
      for (const permission of role.permissions) {
        if (permission.resource === check.resource && permission.action === check.action) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if a user has any of the specified permissions
   */
  async hasAnyPermission(userId: UserId, checks: PermissionCheck[]): Promise<boolean> {
    if (!this.config.enabled) {
      return true;
    }

    for (const check of checks) {
      if (await this.hasPermission(userId, check)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a user has all of the specified permissions
   */
  async hasAllPermissions(userId: UserId, checks: PermissionCheck[]): Promise<boolean> {
    if (!this.config.enabled) {
      return true;
    }

    for (const check of checks) {
      if (!(await this.hasPermission(userId, check))) {
        return false;
      }
    }

    return true;
  }

  /**
   * Get all permissions for a user
   */
  async getUserPermissions(userId: UserId, orgId: OrganizationId): Promise<Result<Permission[]>> {
    const rolesResult = await this.getUserRoles(userId, orgId);
    if (!rolesResult.ok) {
      return rolesResult;
    }

    const userRoles = rolesResult.value;
    const permissions: Permission[] = [];
    const seen = new Set<string>();

    for (const role of userRoles) {
      for (const permission of role.permissions) {
        const key = `${permission.resource}:${permission.action}`;
        if (!seen.has(key)) {
          permissions.push(permission);
          seen.add(key);
        }
      }
    }

    return ok(permissions);
  }

  /**
   * Create predefined system roles
   */
  async createSystemRoles(orgId: OrganizationId): Promise<Result<void>> {
    if (!this.config.enabled) {
      return ok(undefined);
    }

    const adminResult = await this.createRole(
      orgId,
      'Admin',
      [{ id: 'perm_1', name: 'Admin Access', resource: '*', action: '*' }],
      'Full administrative access'
    );

    if (!adminResult.ok) {
      return adminResult;
    }

    const memberResult = await this.createRole(
      orgId,
      'Member',
      [
        { id: 'perm_2', name: 'Read Access', resource: '*', action: 'read' },
        { id: 'perm_3', name: 'Write Access', resource: '*', action: 'write' },
      ],
      'Standard member access'
    );

    if (!memberResult.ok) {
      return memberResult;
    }

    const viewerResult = await this.createRole(
      orgId,
      'Viewer',
      [{ id: 'perm_4', name: 'Read Only', resource: '*', action: 'read' }],
      'Read-only access'
    );

    if (!viewerResult.ok) {
      return viewerResult;
    }

    return ok(undefined);
  }
}

