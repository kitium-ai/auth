import { RBACService } from '../rbac/service';
import { ValidationError, AuthorizationError } from '../errors';

// Mock storage adapter
class MockStorageAdapter {
  private roles: Map<string, any> = new Map();
  private userRoles: Map<string, string[]> = new Map();

  async createRole(data: any) {
    const role = { ...data, id: `role_${Math.random()}` };
    this.roles.set(role.id, role);
    return role;
  }

  async getRole(roleId: string) {
    return this.roles.get(roleId) || null;
  }

  async listRoles(orgId: string) {
    return Array.from(this.roles.values()).filter((r) => r.orgId === orgId);
  }

  async updateRole(roleId: string, updates: any) {
    const role = this.roles.get(roleId);
    if (!role) return null;
    const updated = { ...role, ...updates };
    this.roles.set(roleId, updated);
    return updated;
  }

  async deleteRole(roleId: string) {
    this.roles.delete(roleId);
  }

  async assignRoleToUser(userId: string, roleId: string, orgId: string) {
    const key = `${userId}_${orgId}`;
    const roles = this.userRoles.get(key) || [];
    if (!roles.includes(roleId)) {
      roles.push(roleId);
      this.userRoles.set(key, roles);
    }
  }

  async revokeRoleFromUser(userId: string, roleId: string, orgId: string) {
    const key = `${userId}_${orgId}`;
    const roles = this.userRoles.get(key) || [];
    this.userRoles.set(
      key,
      roles.filter((r) => r !== roleId)
    );
  }

  async getUserRoles(userId: string, orgId: string) {
    const key = `${userId}_${orgId}`;
    const roleIds = this.userRoles.get(key) || [];
    return roleIds.map((id) => this.roles.get(id)).filter(Boolean);
  }
}

describe('RBACService', () => {
  let rbacService: RBACService;
  let mockStorage: MockStorageAdapter;

  beforeEach(() => {
    mockStorage = new MockStorageAdapter();
    rbacService = new RBACService(mockStorage as any, { enabled: true });
  });

  describe('Role Management', () => {
    it('should create a new role', async () => {
      const role = await rbacService.createRole('org_1', 'Admin', [
        { id: 'perm_1', name: 'Full Access', resource: '*', action: '*' },
      ]);

      expect(role).toBeDefined();
      expect(role.name).toBe('Admin');
      expect(role.orgId).toBe('org_1');
      expect(role.permissions).toHaveLength(1);
    });

    it('should throw error if role name is empty', async () => {
      await expect(rbacService.createRole('org_1', '', [])).rejects.toThrow(ValidationError);
    });

    it('should get a role by ID', async () => {
      const created = await rbacService.createRole('org_1', 'Editor', []);
      const retrieved = await rbacService.getRole(created.id);

      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe('Editor');
    });

    it('should list all roles in organization', async () => {
      await rbacService.createRole('org_1', 'Admin', []);
      await rbacService.createRole('org_1', 'Editor', []);
      await rbacService.createRole('org_2', 'Viewer', []);

      const roles = await rbacService.listRoles('org_1');

      expect(roles).toHaveLength(2);
      expect(roles.every((r) => r.orgId === 'org_1')).toBe(true);
    });

    it('should prevent modifying system roles', async () => {
      const role = await rbacService.createRole('org_1', 'Admin', []);
      await mockStorage.updateRole(role.id, { isSystem: true });

      await expect(rbacService.updateRole(role.id, { name: 'SuperAdmin' })).rejects.toThrow(
        AuthorizationError
      );
    });

    it('should prevent deleting system roles', async () => {
      const role = await rbacService.createRole('org_1', 'Admin', []);
      await mockStorage.updateRole(role.id, { isSystem: true });

      await expect(rbacService.deleteRole(role.id)).rejects.toThrow(AuthorizationError);
    });
  });

  describe('Role Assignment', () => {
    it('should assign role to user', async () => {
      const role = await rbacService.createRole('org_1', 'Editor', []);
      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const userRoles = await rbacService.getUserRoles('user_1', 'org_1');
      expect(userRoles).toHaveLength(1);
      expect(userRoles[0].id).toBe(role.id);
    });

    it('should revoke role from user', async () => {
      const role = await rbacService.createRole('org_1', 'Editor', []);
      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');
      await rbacService.revokeRoleFromUser('user_1', role.id, 'org_1');

      const userRoles = await rbacService.getUserRoles('user_1', 'org_1');
      expect(userRoles).toHaveLength(0);
    });
  });

  describe('Permission Checking', () => {
    it('should check if user has permission', async () => {
      const role = await rbacService.createRole('org_1', 'Editor', [
        { id: 'perm_1', name: 'Write', resource: 'docs', action: 'write' },
      ]);

      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const hasPermission = await rbacService.hasPermission('user_1', {
        resource: 'docs',
        action: 'write',
        orgId: 'org_1',
      });

      expect(hasPermission).toBe(true);
    });

    it('should return false for missing permission', async () => {
      const role = await rbacService.createRole('org_1', 'Viewer', [
        { id: 'perm_1', name: 'Read', resource: 'docs', action: 'read' },
      ]);

      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const hasPermission = await rbacService.hasPermission('user_1', {
        resource: 'docs',
        action: 'delete',
        orgId: 'org_1',
      });

      expect(hasPermission).toBe(false);
    });

    it('should get all user permissions', async () => {
      const role = await rbacService.createRole('org_1', 'Admin', [
        { id: 'perm_1', name: 'Read', resource: 'docs', action: 'read' },
        { id: 'perm_2', name: 'Write', resource: 'docs', action: 'write' },
      ]);

      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const permissions = await rbacService.getUserPermissions('user_1', 'org_1');

      expect(permissions).toHaveLength(2);
      expect(permissions.some((p) => p.action === 'read')).toBe(true);
      expect(permissions.some((p) => p.action === 'write')).toBe(true);
    });

    it('should check any permission', async () => {
      const role = await rbacService.createRole('org_1', 'Editor', [
        { id: 'perm_1', name: 'Write', resource: 'docs', action: 'write' },
      ]);

      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const hasAny = await rbacService.hasAnyPermission('user_1', [
        { resource: 'docs', action: 'delete', orgId: 'org_1' },
        { resource: 'docs', action: 'write', orgId: 'org_1' },
      ]);

      expect(hasAny).toBe(true);
    });

    it('should check all permissions', async () => {
      const role = await rbacService.createRole('org_1', 'Editor', [
        { id: 'perm_1', name: 'Write', resource: 'docs', action: 'write' },
        { id: 'perm_2', name: 'Delete', resource: 'docs', action: 'delete' },
      ]);

      await rbacService.assignRoleToUser('user_1', role.id, 'org_1');

      const hasAll = await rbacService.hasAllPermissions('user_1', [
        { resource: 'docs', action: 'write', orgId: 'org_1' },
        { resource: 'docs', action: 'delete', orgId: 'org_1' },
      ]);

      expect(hasAll).toBe(true);
    });
  });

  describe('RBAC Disabled', () => {
    it('should throw error when RBAC is disabled', async () => {
      const disabledService = new RBACService(mockStorage as any, { enabled: false });

      await expect(disabledService.createRole('org_1', 'Admin', [])).rejects.toThrow(
        ValidationError
      );
    });
  });
});
