import { createLogger } from '@kitiumai/logger';
import { nanoid } from 'nanoid';

export type ScimUser = {
  id: string;
  userName: string;
  active: boolean;
  emails: Array<{ value: string; primary?: boolean }>;
  name?: { givenName?: string; familyName?: string };
  groups?: string[];
  meta?: Record<string, unknown>;
};

export type ScimProvisioningResult = {
  id: string;
  status: 'created' | 'updated' | 'deactivated';
  timestamp: Date;
  payload: ScimUser;
};

export type JitProfile = {
  email: string;
  provider: 'saml' | 'oidc';
  attributes?: Record<string, unknown>;
};

export type JitResult = {
  userId: string;
  organizationId?: string;
  created: boolean;
  mappedAttributes?: Record<string, unknown>;
};

export class ProvisioningService {
  private readonly users = new Map<string, ScimUser>();
  private readonly logger = createLogger();

  async upsertScimUser(
    payload: Omit<ScimUser, 'id'> & { id?: string }
  ): Promise<ScimProvisioningResult> {
    const id = payload.id ?? nanoid();
    const next: ScimUser = { ...payload, id };
    const exists = this.users.has(id);
    this.users.set(id, next);

    const status: ScimProvisioningResult['status'] =
      payload.active === false ? 'deactivated' : exists ? 'updated' : 'created';
    this.logger.info('SCIM user upserted', { id, status });
    return { id, status, timestamp: new Date(), payload: next };
  }

  async deactivateUser(id: string): Promise<ScimProvisioningResult> {
    const user = this.users.get(id);
    if (!user) {
      throw new Error('User not found');
    }
    const payload: ScimUser = { ...user, active: false };
    this.users.set(id, payload);
    return { id, status: 'deactivated', timestamp: new Date(), payload };
  }

  async jitProvision(profile: JitProfile): Promise<JitResult> {
    const existing = Array.from(this.users.values()).find((user) =>
      user.emails.some((email) => email.value.toLowerCase() === profile.email.toLowerCase())
    );

    if (existing) {
      return { userId: existing.id, created: false, mappedAttributes: profile.attributes };
    }

    const user: ScimUser = {
      id: nanoid(),
      userName: profile.email,
      active: true,
      emails: [{ value: profile.email, primary: true }],
      meta: { provider: profile.provider },
    };

    this.users.set(user.id, user);
    this.logger.info('JIT provisioned user', { userId: user.id, provider: profile.provider });
    return { userId: user.id, created: true, mappedAttributes: profile.attributes };
  }

  list(): ScimUser[] {
    return Array.from(this.users.values());
  }
}
