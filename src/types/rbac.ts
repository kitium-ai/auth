// Enhanced RBAC (Role-Based Access Control) types

export interface Permission {
  id: string;
  name: string;
  description?: string;
  resource: string;
  action: string; // e.g., 'read', 'write', 'delete', 'admin'
  metadata?: Record<string, any>;
}

export interface Role {
  id: string;
  orgId: string;
  name: string;
  description?: string;
  permissions: Permission[];
  isSystem?: boolean; // System roles cannot be modified
  createdAt: Date;
  updatedAt: Date;
}

export interface CustomRole {
  id: string;
  orgId: string;
  userId: string;
  roleId: string;
  role: Role;
  assignedAt: Date;
}

export interface PermissionCheck {
  resource: string;
  action: string;
  orgId?: string;
}

export interface RBACConfig {
  enabled: boolean;
  defaultRoles?: string[]; // IDs of default roles to assign
  customRolesAllowed?: boolean;
  hierarchySupport?: boolean;
}

export interface RoleRecord {
  id: string;
  orgId: string;
  name: string;
  description?: string;
  permissions: Permission[];
  isSystem: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface CustomRoleRecord {
  id: string;
  orgId: string;
  userId: string;
  roleId: string;
  assignedAt: Date;
}
