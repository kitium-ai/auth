import { nanoid } from 'nanoid';

export type TenantRegionPolicy = {
  region: string;
  residencyRequired?: boolean;
  encryptionKeyId?: string;
};

export type Tenant = {
  id: string;
  name: string;
  regionPolicy: TenantRegionPolicy;
  providers?: string[];
  featureFlags?: Record<string, boolean>;
  createdAt: Date;
};

export class TenantRegistry {
  private readonly tenants = new Map<string, Tenant>();

  createTenant(name: string, regionPolicy: TenantRegionPolicy, providers?: string[]): Tenant {
    const tenant: Tenant = {
      id: nanoid(),
      name,
      regionPolicy,
      providers,
      featureFlags: {},
      createdAt: new Date(),
    };
    this.tenants.set(tenant.id, tenant);
    return tenant;
  }

  setFeatureFlag(tenantId: string, flag: string, enabled: boolean): Tenant {
    const tenant = this.requireTenant(tenantId);
    tenant.featureFlags = { ...(tenant.featureFlags ?? {}), [flag]: enabled };
    this.tenants.set(tenantId, tenant);
    return tenant;
  }

  updateProviders(tenantId: string, providers: string[]): Tenant {
    const tenant = this.requireTenant(tenantId);
    tenant.providers = providers;
    this.tenants.set(tenantId, tenant);
    return tenant;
  }

  list(): Tenant[] {
    return Array.from(this.tenants.values());
  }

  private requireTenant(id: string): Tenant {
    const tenant = this.tenants.get(id);
    if (!tenant) {
      throw new Error('Tenant not found');
    }
    return tenant;
  }
}
