// Enhanced RBAC (Role-Based Access Control) types

export type Permission = {
  id: string;
  name: string;
  description?: string;
  resource: string;
  action: string; // e.g., 'read', 'write', 'delete', 'admin'
  metadata?: Record<string, unknown>;
};

export type Role = {
  id: string;
  orgId: string;
  name: string;
  description?: string;
  permissions: Permission[];
  isSystem?: boolean; // System roles cannot be modified
  createdAt: Date;
  updatedAt: Date;
};

export type CustomRole = {
  id: string;
  orgId: string;
  userId: string;
  roleId: string;
  role: Role;
  assignedAt: Date;
};

export type PermissionCheck = {
  resource: string;
  action: string;
  orgId?: string;
};

export type RBACConfig = {
  enabled: boolean;
  defaultRoles?: string[]; // IDs of default roles to assign
  customRolesAllowed?: boolean;
  hierarchySupport?: boolean;
};

export type RoleRecord = {
  id: string;
  orgId: string;
  name: string;
  description?: string;
  permissions: Permission[];
  isSystem: boolean;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
};

export type CustomRoleRecord = {
  id: string;
  orgId: string;
  userId: string;
  roleId: string;
  assignedAt: Date;
};
