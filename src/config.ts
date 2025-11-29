/**
 * Auth configuration system
 * Environment-aware configuration for authentication
 */

import { ValidationError } from '@kitiumai/error';

/**
 * Auth provider configuration
 */
export interface AuthProvider {
  id: string;
  name: string;
  type: 'oauth' | 'email' | 'saml';
  enabled: boolean;
  config?: Record<string, unknown>;
}

/**
 * Storage configuration
 */
export interface StorageConfig {
  type: 'memory' | 'postgres' | 'mongodb' | 'custom';
  connectionString?: string;
  options?: Record<string, unknown>;
}

/**
 * Billing configuration
 */
export interface BillingConfig {
  enabled: boolean;
  provider?: 'stripe' | 'custom';
  apiKey?: string;
  webhookSecret?: string;
}

/**
 * Billing product definition
 */
export interface BillingProduct {
  id: string;
  name: string;
  description?: string;
  features: string[];
  price?: number;
  currency?: string;
}

/**
 * API key configuration
 */
export interface ApiKeyConfig {
  enabled: boolean;
  expirationDays?: number;
  rotationRequired?: boolean;
}

/**
 * Session configuration
 */
export interface SessionConfig {
  enabled: boolean;
  expirationMinutes?: number;
  refreshTokenExpirationDays?: number;
  sameSite?: 'strict' | 'lax' | 'none';
  secure?: boolean;
  httpOnly?: boolean;
}

/**
 * Organization configuration
 */
export interface OrganizationConfig {
  enabled: boolean;
  multiTenant?: boolean;
  defaultRole?: string;
}

/**
 * Event configuration
 */
export interface EventConfig {
  enabled: boolean;
  webhookUrl?: string;
  events?: string[];
}

/**
 * Main auth configuration
 */
export interface AuthConfig {
  appName: string;
  appUrl: string;
  apiUrl: string;
  jwtSecret: string;
  providers: AuthProvider[];
  storage: StorageConfig;
  billing?: BillingConfig;
  apiKey?: ApiKeyConfig;
  session?: SessionConfig;
  organization?: OrganizationConfig;
  events?: EventConfig;
}

/**
 * Define auth configuration
 */
export function defineConfig(config: Partial<AuthConfig>): AuthConfig {
  const defaults: AuthConfig = {
    appName: 'My App',
    appUrl: getEnvVar('APP_URL') || 'http://localhost:3000',
    apiUrl: getEnvVar('API_URL') || 'http://localhost:3000/api',
    jwtSecret: getEnvVar('JWT_SECRET', true),
    providers: [],
    storage: {
      type: 'memory',
    },
  };

  return { ...defaults, ...config };
}

/**
 * Create OAuth provider configuration
 */
export function createOAuthProvider(id: string, config: Record<string, unknown>): AuthProvider {
  return {
    id,
    name: (config['name'] as string) || id,
    type: 'oauth',
    enabled: (config['enabled'] as boolean) ?? true,
    config,
  };
}

/**
 * Create OAuth/email provider configuration
 */
export function createProvider(id: string, config: Record<string, unknown>): AuthProvider {
  const type = (config['type'] as string) || 'oauth';
  return {
    id,
    name: (config['name'] as string) || id,
    type: type as 'oauth' | 'email' | 'saml',
    enabled: (config['enabled'] as boolean) ?? true,
    config,
  };
}

/**
 * Create email provider configuration
 */
export function createEmailProvider(config: Record<string, unknown>): AuthProvider {
  return {
    id: 'email',
    name: 'Email',
    type: 'email',
    enabled: (config['enabled'] as boolean) ?? true,
    config,
  };
}

/**
 * Create storage configuration
 */
export function createStorageConfig(config: StorageConfig): StorageConfig {
  return {
    ...config,
    type: config.type || 'memory',
  };
}

/**
 * Create billing configuration
 */
export function createBillingConfig(config: Partial<BillingConfig>): BillingConfig {
  return {
    enabled: false,
    ...config,
  };
}

/**
 * Create API key configuration
 */
export function createApiKeyConfig(config: Partial<ApiKeyConfig>): ApiKeyConfig {
  return {
    enabled: true,
    expirationDays: 365,
    ...config,
  };
}

/**
 * Create session configuration
 */
export function createSessionConfig(config: Partial<SessionConfig>): SessionConfig {
  return {
    enabled: true,
    expirationMinutes: 60,
    refreshTokenExpirationDays: 7,
    sameSite: 'lax',
    secure: false,
    httpOnly: true,
    ...config,
  };
}

/**
 * Create organization configuration
 */
export function createOrganizationConfig(config: Partial<OrganizationConfig>): OrganizationConfig {
  return {
    enabled: false,
    multiTenant: false,
    ...config,
  };
}

/**
 * Create event configuration
 */
export function createEventConfig(config: Partial<EventConfig>): EventConfig {
  return {
    enabled: false,
    ...config,
  };
}

/**
 * Validate auth configuration
 */
export function validateConfig(config: AuthConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!config.appName) {
    errors.push('appName is required');
  }

  if (!config.appUrl) {
    errors.push('appUrl is required');
  }

  if (!config.jwtSecret) {
    errors.push('jwtSecret is required');
  }

  if (config.jwtSecret && config.jwtSecret.length < 32) {
    errors.push('jwtSecret must be at least 32 characters');
  }

  if (!config.storage || !config.storage.type) {
    errors.push('storage configuration is required');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get environment variable with optional requirement
 */
export function getEnvVar(name: string, required: boolean = false): string {
  const value = process.env[name];

  if (required && !value) {
    throw new ValidationError({
      code: 'auth/missing_env_var',
      message: `Environment variable ${name} is required`,
      severity: 'error',
      retryable: false,
      context: { name },
    });
  }

  return value || '';
}

/**
 * Get environment variable as number
 */
export function getEnvVarAsNumber(name: string, defaultValue: number = 0): number {
  const value = getEnvVar(name);
  return value ? Number.parseInt(value, 10) : defaultValue;
}

/**
 * Get environment variable as boolean
 */
export function getEnvVarAsBoolean(name: string, defaultValue: boolean = false): boolean {
  const value = getEnvVar(name);
  if (!value) {
    return defaultValue;
  }
  return value.toLowerCase() === 'true' || value === '1';
}
