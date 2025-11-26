import { nanoid } from 'nanoid';
import { getLogger } from '@kitiumai/logger';
import { Permission, Role, RoleRecord, PermissionCheck, RBACConfig, CustomRole } from '../types';
import { AuthorizationError, ValidationError } from '../errors';
import { StorageAdapter } from '../types';

/**
 * RBAC (Role-Based Access Control) Service
 * Manages roles, permissions, and role assignments
 */
export class RBACService {
  private storage: StorageAdapter;
  private config: RBACConfig;
  private logger = getLogger();

  constructor(storage: StorageAdapter, config: RBACConfig = { enabled: false }) {
    this.storage = storage;
    this.config = config;
    this.logger.debug('RBACService initialized', { enabled: config.enabled });
  }

  /**
   * Create a new role with permissions
   */
  async createRole(
    orgId: string,
    name: string,
    permissions: Permission[],
    description?: string
  ): Promise<Role> {
    if (!this.config.enabled) {
      this.logger.warn('Role creation attempted when RBAC disabled', { orgId });
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    if (!name || name.trim().length === 0) {
      this.logger.warn('Role creation attempted with invalid name', { orgId });
      throw new ValidationError({
        code: 'auth/role_name_required',
        message: 'Role name is required',
      });
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
      throw new ValidationError({
        code: 'auth/storage_adapter_not_supported',
        message: 'Role creation is not supported by storage adapter',
      });
    }

    return this.storage.createRole(role);
  }

  /**
   * Get a role by ID
   */
  async getRole(roleId: string): Promise<Role | null> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    if (!this.storage.getRole) {
      return null;
    }

    return this.storage.getRole(roleId);
  }

  /**
   * List all roles in an organization
   */
  async listRoles(orgId: string): Promise<Role[]> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    if (!this.storage.listRoles) {
      return [];
    }

    return this.storage.listRoles(orgId);
  }

  /**
   * Update a role
   */
  async updateRole(roleId: string, updates: Partial<Role>): Promise<Role> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    const role = await this.getRole(roleId);
    if (!role) {
      throw new ValidationError({
        code: 'auth/role_not_found',
        message: `Role not found: ${roleId}`,
        context: { roleId },
      });
    }

    if (role.isSystem) {
      throw new AuthorizationError({
        code: 'auth/system_role_immutable',
        message: 'System roles cannot be modified',
      });
    }

    if (!this.storage.updateRole) {
      throw new ValidationError({
        code: 'auth/role_update_not_supported',
        message: 'Role update is not supported by storage adapter',
      });
    }

    return this.storage.updateRole(roleId, {
      ...updates,
      updatedAt: new Date(),
    });
  }

  /**
   * Delete a role
   */
  async deleteRole(roleId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    const role = await this.getRole(roleId);
    if (!role) {
      throw new ValidationError({
        code: 'auth/role_not_found',
        message: `Role not found: ${roleId}`,
        context: { roleId },
      });
    }

    if (role.isSystem) {
      throw new AuthorizationError({
        code: 'auth/system_role_immutable',
        message: 'System roles cannot be deleted',
      });
    }

    if (!this.storage.deleteRole) {
      throw new ValidationError({
        code: 'auth/role_deletion_not_supported',
        message: 'Role deletion is not supported by storage adapter',
      });
    }

    return this.storage.deleteRole(roleId);
  }

  /**
   * Assign a role to a user
   */
  async assignRoleToUser(userId: string, roleId: string, orgId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    const role = await this.getRole(roleId);
    if (!role) {
      throw new ValidationError({
        code: 'auth/role_not_found',
        message: `Role not found: ${roleId}`,
        context: { roleId },
      });
    }

    if (role.orgId !== orgId) {
      throw new AuthorizationError({
        code: 'auth/role_org_mismatch',
        message: 'Role does not belong to organization',
      });
    }

    if (!this.storage.assignRoleToUser) {
      throw new ValidationError({
        code: 'auth/role_assignment_not_supported',
        message: 'Role assignment is not supported by storage adapter',
      });
    }

    await this.storage.assignRoleToUser(userId, roleId, orgId);
  }

  /**
   * Revoke a role from a user
   */
  async revokeRoleFromUser(userId: string, roleId: string, orgId: string): Promise<void> {
    if (!this.config.enabled) {
      throw new ValidationError({
        code: 'auth/rbac_not_enabled',
        message: 'RBAC is not enabled',
      });
    }

    if (!this.storage.revokeRoleFromUser) {
      throw new ValidationError({
        code: 'auth/role_revocation_not_supported',
        message: 'Role revocation is not supported by storage adapter',
      });
    }

    await this.storage.revokeRoleFromUser(userId, roleId, orgId);
  }

  /**
   * Get all roles assigned to a user in an organization
   */
  async getUserRoles(userId: string, orgId: string): Promise<Role[]> {
    if (!this.config.enabled) {
      return [];
    }

    if (!this.storage.getUserRoles) {
      return [];
    }

    return this.storage.getUserRoles(userId, orgId);
  }

  /**
   * Check if a user has a specific permission
   */
  async hasPermission(userId: string, check: PermissionCheck): Promise<boolean> {
    if (!this.config.enabled) {
      return true; // RBAC disabled, allow all
    }

    const userRoles = await this.getUserRoles(userId, check.orgId || '');

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
  async hasAnyPermission(userId: string, checks: PermissionCheck[]): Promise<boolean> {
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
  async hasAllPermissions(userId: string, checks: PermissionCheck[]): Promise<boolean> {
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
  async getUserPermissions(userId: string, orgId: string): Promise<Permission[]> {
    const userRoles = await this.getUserRoles(userId, orgId);
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

    return permissions;
  }

  /**
   * Create predefined system roles
   */
  async createSystemRoles(orgId: string): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    const adminRole = await this.createRole(
      orgId,
      'Admin',
      [{ id: 'perm_1', name: 'Admin Access', resource: '*', action: '*' }],
      'Full administrative access'
    );

    const memberRole = await this.createRole(
      orgId,
      'Member',
      [
        { id: 'perm_2', name: 'Read Access', resource: '*', action: 'read' },
        { id: 'perm_3', name: 'Write Access', resource: '*', action: 'write' },
      ],
      'Standard member access'
    );

    const viewerRole = await this.createRole(
      orgId,
      'Viewer',
      [{ id: 'perm_4', name: 'Read Only', resource: '*', action: 'read' }],
      'Read-only access'
    );
  }
}
