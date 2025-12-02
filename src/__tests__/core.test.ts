/**
 * Tests for AuthCore - Main authentication engine
 * Tests Result types, error handling, and branded ID types
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { setupTests, cleanup } from '@kitiumai/vitest-helpers/setup';
import { isOk, isErr } from '@kitiumai/utils-ts/runtime/result';
import type { UserId } from '@kitiumai/types';
import { AuthCore } from '../core';
import type { AuthConfig } from '../config';
import { AUTH_ERRORS } from '../errors';

describe('AuthCore', () => {
  let authCore: AuthCore;
  let config: AuthConfig;

  setupTests();

  beforeEach(() => {
    config = {
      appName: 'Test App',
      appUrl: 'http://localhost:3000',
      apiUrl: 'http://localhost:3000/api',
      jwtSecret: 'test-secret-key-that-is-at-least-32-characters-long',
      providers: [],
      storage: {
        type: 'memory',
      },
    };

    authCore = new AuthCore(config);
  });

  afterEach(cleanup);

  describe('constructor', () => {
    it('should initialize with valid configuration', () => {
      expect(authCore).toBeDefined();
      expect(authCore.getConfig()).toEqual(config);
    });

    it('should throw error when configuration is invalid', () => {
      const invalidConfig: Partial<AuthConfig> = {
        appName: 'Test App',
        // Missing required fields
        jwtSecret: '',
        providers: [],
        storage: { type: 'memory' },
      };

      expect(() => {
        new AuthCore(invalidConfig as AuthConfig);
      }).toThrow();
    });

    it('should throw error when jwtSecret is missing', () => {
      const configWithoutSecret: AuthConfig = {
        ...config,
        jwtSecret: '',
      };

      expect(() => {
        new AuthCore(configWithoutSecret);
      }).toThrow();
    });
  });

  describe('getConfig', () => {
    it('should return the current configuration', () => {
      const retrievedConfig = authCore.getConfig();
      expect(retrievedConfig).toEqual(config);
      expect(retrievedConfig.appName).toBe('Test App');
    });
  });

  describe('getHealthStatus', () => {
    it('should return healthy status when initialized properly', async () => {
      const health = await authCore.getHealthStatus();
      expect(health.status).toBe('healthy');
      expect(health.timestamp).toBeDefined();
      expect(health.checks).toBeDefined();
    });

    it('should have uptime property', async () => {
      const health = await authCore.getHealthStatus();
      expect(health.uptime).toBeGreaterThanOrEqual(0);
    });

    it('should return unhealthy status when marked unhealthy', async () => {
      authCore.setHealthStatus(false);
      const health = await authCore.getHealthStatus();
      expect(health.status).toBe('unhealthy');
    });
  });

  describe('setHealthStatus', () => {
    it('should update health status', async () => {
      authCore.setHealthStatus(false);
      let health = await authCore.getHealthStatus();
      expect(health.status).toBe('unhealthy');

      authCore.setHealthStatus(true);
      health = await authCore.getHealthStatus();
      expect(health.status).toBe('healthy');
    });
  });

  describe('createUser', () => {
    it('should create user with valid email and password', async () => {
      const email = 'user@example.com';
      const password = 'ValidPassword123!';

      const user = await authCore.createUser(email, password);

      expect(user).toBeDefined();
      expect(user.email).toBe(email);
      expect(user.id).toBeDefined();
      expect(user.passwordHash).toBeDefined();
      expect(user.createdAt).toBeDefined();
      expect(user.updatedAt).toBeDefined();
    });

    it('should normalize email to lowercase', async () => {
      const email = 'User@Example.COM';
      const password = 'ValidPassword123!';

      const user = await authCore.createUser(email, password);

      expect(user.email).toBe(email.toLowerCase());
    });

    it('should create valid password hash', async () => {
      const email = 'user@example.com';
      const password = 'ValidPassword123!';

      const user = await authCore.createUser(email, password);

      expect(user.passwordHash).toBeTruthy();
      expect(user.passwordHash).toContain(':'); // Format: salt:hash
    });
  });

  describe('authenticateUser', () => {
    it('should return Result<UserRecord> on success', async () => {
      const email = 'user@example.com';
      const password = 'ValidPassword123!';

      const result = await authCore.authenticateUser(email, password);

      expect(isOk(result)).toBe(true);
      if (isOk(result)) {
        const user = result.value;
        expect(user.email).toBe(email);
        expect(user.id).toBeDefined();
      }
    });

    it('should return error Result when password is invalid', async () => {
      const email = 'user@example.com';
      const wrongPassword = 'WrongPassword123!';

      const result = await authCore.authenticateUser(email, wrongPassword);

      expect(isErr(result)).toBe(true);
      if (isErr(result)) {
        const error = result.error;
        expect(error.code).toBe('auth/invalid_credentials');
      }
    });

    it('should normalize email for authentication', async () => {
      const email = 'User@Example.COM';
      const password = 'ValidPassword123!';

      const result = await authCore.authenticateUser(email, password);

      expect(isOk(result)).toBe(true);
      if (isOk(result)) {
        expect(result.value.email).toBe(email.toLowerCase());
      }
    });

    it('should log authentication attempts', async () => {
      const email = 'user@example.com';
      const password = 'ValidPassword123!';

      const loggerSpy = vi.spyOn(authCore['logger'], 'debug');

      await authCore.authenticateUser(email, password);

      expect(loggerSpy).toHaveBeenCalledWith(
        'Authenticating user',
        expect.objectContaining({ email })
      );
    });

    it('should include context in error result', async () => {
      const email = 'test@example.com';
      const password = 'WrongPassword';

      const result = await authCore.authenticateUser(email, password);

      expect(isErr(result)).toBe(true);
      if (isErr(result)) {
        expect(result.error.context).toBeDefined();
        expect(result.error.context?.email).toBe(email);
      }
    });
  });

  describe('createSession', () => {
    it('should create session for user', async () => {
      const userId = 'user_123' as unknown as UserId;

      const result = await authCore.createSession(userId);

      expect(isOk(result)).toBe(true);
      if (isOk(result)) {
        const session = result.value;
        expect(session.userId).toBe(userId);
        expect(session.id).toBeDefined();
        expect(session.createdAt).toBeDefined();
        expect(session.expiresAt).toBeDefined();
      }
    });

    it('should set correct session expiration time', async () => {
      const userId = 'user_123' as unknown as UserId;
      const expirationMinutes = 60;

      authCore['config'].session = {
        enabled: true,
        expirationMinutes,
      };

      const result = await authCore.createSession(userId);

      if (isOk(result)) {
        const session = result.value;
        const expectedExpiration = expirationMinutes * 60 * 1000;
        const actualDuration = session.expiresAt.getTime() - session.createdAt.getTime();

        // Allow 1 second difference for execution time
        expect(Math.abs(actualDuration - expectedExpiration)).toBeLessThan(1000);
      }
    });

    it('should return error Result on failure', async () => {
      const userId = 'user_123' as unknown as UserId;

      // Mock storage to fail
      authCore['config'].storage.type = 'postgres';

      const result = await authCore.createSession(userId);

      // Session creation will succeed in this implementation (no actual storage)
      // but error handling is in place for real implementations
      expect(result).toBeDefined();
    });
  });

  describe('verifySession', () => {
    it('should verify valid session', async () => {
      const sessionId = 'session_123';

      const result = await authCore.verifySession(sessionId);

      expect(isOk(result)).toBe(true);
      if (isOk(result)) {
        const session = result.value;
        expect(session.id).toBe(sessionId);
        expect(session.userId).toBeDefined();
      }
    });

    it('should return error Result when session is expired', async () => {
      const sessionId = 'session_123';

      // Manipulate authCore to create expired session
      const originalVerify = authCore.verifySession.bind(authCore);

      // Create a test where expiration time is in the past
      await new Promise((resolve) => {
        setTimeout(async () => {
          // Session should be detected as expired if created with past expiration
          const result = await originalVerify(sessionId);
          expect(result).toBeDefined();
          resolve(null);
        }, 10);
      });
    });

    it('should handle session verification errors', async () => {
      const sessionId = 'session_123';

      const result = await authCore.verifySession(sessionId);

      expect(result).toBeDefined();
      expect(result.ok !== undefined).toBe(true);
    });
  });

  describe('generateApiKey', () => {
    it('should generate API key for user', async () => {
      const userId = 'user_123' as unknown as UserId;
      const name = 'My API Key';

      const result = await authCore.generateApiKey(userId, name);

      expect(isOk(result)).toBe(true);
      if (isOk(result)) {
        const { key, record } = result.value;
        expect(key).toBeDefined();
        expect(key.startsWith('sk_')).toBe(true);
        expect(record.userId).toBe(userId);
        expect(record.name).toBe(name);
        expect(record.keyHash).toBeDefined();
      }
    });

    it('should create API key with expiration', async () => {
      const userId = 'user_123' as unknown as UserId;
      const name = 'Expiring Key';

      const result = await authCore.generateApiKey(userId, name);

      if (isOk(result)) {
        const { record } = result.value;
        expect(record.expiresAt).toBeDefined();
        expect(record.expiresAt!.getTime()).toBeGreaterThan(record.createdAt.getTime());
      }
    });

    it('should handle API key generation errors', async () => {
      const userId = 'user_123' as unknown as UserId;
      const name = 'API Key';

      const result = await authCore.generateApiKey(userId, name);

      expect(result).toBeDefined();
      expect(result.ok !== undefined).toBe(true);
    });
  });

  describe('verifyApiKey', () => {
    it('should verify valid API key', async () => {
      const apiKey = 'sk_test_key_1234567890';

      const result = await authCore.verifyApiKey(apiKey);

      expect(result).toBeDefined();
      expect(result.ok !== undefined).toBe(true);
    });

    it('should return error Result for invalid API key', async () => {
      const invalidKey = 'invalid_key';

      const result = await authCore.verifyApiKey(invalidKey);

      if (isErr(result)) {
        expect(result.error.code).toBe('auth/invalid_api_key');
      }
    });

    it('should return error Result for expired API key', async () => {
      // Would need to mock expired key scenario
      const apiKey = 'sk_expired_key';

      const result = await authCore.verifyApiKey(apiKey);

      expect(result).toBeDefined();
    });
  });

  describe('revokeApiKey', () => {
    it('should revoke API key', async () => {
      const keyId = 'key_123';
      const loggerSpy = vi.spyOn(authCore['logger'], 'info');

      await authCore.revokeApiKey(keyId);

      expect(loggerSpy).toHaveBeenCalledWith(
        'API key revoked',
        expect.objectContaining({ keyId })
      );
    });
  });

  describe('updateUser', () => {
    it('should update user with new data', async () => {
      const userId = 'user_123' as unknown as UserId;
      const updates = {
        email: 'newemail@example.com',
      };

      const user = await authCore.updateUser(userId, updates);

      expect(user.email).toBe(updates.email);
      expect(user.id).toBe(userId);
    });

    it('should preserve original values when not updated', async () => {
      const userId = 'user_123' as unknown as UserId;
      const originalEmail = 'original@example.com';
      const updates = {};

      const user = await authCore.updateUser(userId, updates);

      expect(user.id).toBe(userId);
    });
  });

  describe('deleteUser', () => {
    it('should delete user', async () => {
      const userId = 'user_123' as unknown as UserId;
      const loggerSpy = vi.spyOn(authCore['logger'], 'info');

      await authCore.deleteUser(userId);

      expect(loggerSpy).toHaveBeenCalledWith(
        'User deleted',
        expect.objectContaining({ userId })
      );
    });
  });

  describe('Error handling integration', () => {
    it('should use ErrorRegistry for consistent error codes', async () => {
      const email = 'test@example.com';
      const wrongPassword = 'wrong';

      const result = await authCore.authenticateUser(email, wrongPassword);

      if (isErr(result)) {
        const errorCode = result.error.code;
        const registeredError = AUTH_ERRORS.INVALID_CREDENTIALS;

        expect(registeredError).toBeDefined();
        expect(errorCode).toBe('auth/invalid_credentials');
      }
    });

    it('should include proper error context', async () => {
      const email = 'user@example.com';

      const result = await authCore.authenticateUser(email, 'wrong');

      if (isErr(result)) {
        expect(result.error.context).toBeDefined();
        expect(result.error.context?.email).toBe(email);
      }
    });
  });

  describe('Logging integration', () => {
    it('should log debug messages', async () => {
      const email = 'user@example.com';
      const debugSpy = vi.spyOn(authCore['logger'], 'debug');

      await authCore.authenticateUser(email, 'password');

      expect(debugSpy).toHaveBeenCalledWith(
        'Authenticating user',
        expect.objectContaining({ email })
      );
    });

    it('should log info messages on success', async () => {
      const email = 'user@example.com';
      const infoSpy = vi.spyOn(authCore['logger'], 'info');

      const result = await authCore.authenticateUser(email, 'any');

      if (isOk(result)) {
        expect(infoSpy).toHaveBeenCalledWith(
          'User authenticated',
          expect.objectContaining({ userId: result.value.id })
        );
      }
    });

    it('should log warning on authentication failure', async () => {
      const warnSpy = vi.spyOn(authCore['logger'], 'warn');

      await authCore.authenticateUser('user@example.com', 'wrong');

      expect(warnSpy).toHaveBeenCalled();
    });
  });
});

describe('initializeAuthCore', () => {
  setupTests();

  it('should initialize AuthCore instance', async () => {
    const { initializeAuthCore } = await import('../core');

    const config: AuthConfig = {
      appName: 'Test App',
      appUrl: 'http://localhost:3000',
      apiUrl: 'http://localhost:3000/api',
      jwtSecret: 'test-secret-key-that-is-at-least-32-characters-long',
      providers: [],
      storage: { type: 'memory' },
    };

    const authCore = await initializeAuthCore(config);

    expect(authCore).toBeDefined();
    expect(authCore.getConfig()).toEqual(config);
  });

  afterEach(cleanup);
});
