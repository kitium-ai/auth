/**
 * Auth configuration system
 * Environment-aware configuration for authentication
 * Uses @kitiumai/error for validation and structured error handling
 */

import { createError } from './errors';

/**
 * Configuration validation result
 */
export type ValidationResult = {
  valid: boolean;
  errors: string[];
  warnings?: string[];
};

/**
 * Auth provider configuration
 */
export type AuthProvider = {
  id: string;
  name: string;
  type: 'oauth' | 'email' | 'saml';
  enabled: boolean;
  config?: Record<string, unknown>;
};

/**
 * Storage configuration
 */
export type StorageConfig = {
  type: 'memory' | 'postgres' | 'mongodb' | 'custom';
  connectionString?: string;
  options?: Record<string, unknown>;
};

/**
 * Billing configuration
 */
export type BillingConfig = {
  enabled: boolean;
  provider?: 'stripe' | 'custom';
  apiKey?: string;
  webhookSecret?: string;
};

/**
 * Billing product definition
 */
export type BillingProduct = {
  id: string;
  name: string;
  description?: string;
  features: string[];
  price?: number;
  currency?: string;
};

/**
 * API key configuration
 */
export type ApiKeyConfig = {
  enabled: boolean;
  expirationDays?: number;
  rotationRequired?: boolean;
};

/**
 * Session configuration
 */
export type SessionConfig = {
  enabled: boolean;
  expirationMinutes?: number;
  refreshTokenExpirationDays?: number;
  sameSite?: 'strict' | 'lax' | 'none';
  secure?: boolean;
  httpOnly?: boolean;
};

/**
 * Organization configuration
 */
export type OrganizationConfig = {
  enabled: boolean;
  multiTenant?: boolean;
  defaultRole?: string;
};

/**
 * Event configuration
 */
export type EventConfig = {
  enabled: boolean;
  webhookUrl?: string;
  events?: string[];
};

/**
 * Main auth configuration
 */
export type AuthConfig = {
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
};

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
 * Validate auth configuration with comprehensive checks
 */
export function validateConfig(config: AuthConfig): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Required fields
  if (!config.appName) {
    errors.push('appName is required');
  }

  if (!config.appUrl) {
    errors.push('appUrl is required');
  } else {
    // Validate URL format
    try {
      new URL(config.appUrl);
    } catch {
      errors.push('appUrl must be a valid URL');
    }
  }

  if (!config.jwtSecret) {
    errors.push('jwtSecret is required');
  }

  // Security validations
  if (config.jwtSecret && config.jwtSecret.length < 32) {
    errors.push('jwtSecret must be at least 32 characters for adequate security');
  }

  if (config.jwtSecret && config.jwtSecret === process.env['JWT_SECRET']) {
    warnings.push('jwtSecret appears to be from environment - ensure it is changed in production');
  }

  if (!config.storage?.type) {
    errors.push('storage configuration is required');
  }

  // Session configuration validation
  if (config.session?.secure === false && process.env['NODE_ENV'] === 'production') {
    warnings.push('session.secure should be true in production for HTTPS');
  }

  if (config.session?.httpOnly === false) {
    warnings.push('session.httpOnly should be true to prevent XSS attacks');
  }

  // Provider validation
  if (config.providers?.length === 0) {
    warnings.push('No authentication providers configured - users cannot log in');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings: warnings.length > 0 ? warnings : undefined,
  };
}

/**
 * Get environment variable with optional requirement
 * @throws ValidationError if required variable is missing
 */
export function getEnvVar(name: string, required = false): string {
  const value = process.env[name];

  if (required && !value) {
    throw createError('auth/missing_env_var', {
      message: `Environment variable ${name} is required`,
      context: { name },
    });
  }

  return value || '';
}

/**
 * Get environment variable as number
 */
export function getEnvVarAsNumber(name: string, defaultValue = 0): number {
  const value = getEnvVar(name);
  return value ? Number.parseInt(value, 10) : defaultValue;
}

/**
 * Get environment variable as boolean
 */
export function getEnvVarAsBoolean(name: string, defaultValue = false): boolean {
  const value = getEnvVar(name);
  if (!value) {
    return defaultValue;
  }
  return value.toLowerCase() === 'true' || value === '1';
}
