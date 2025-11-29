/**
 * Hook Manager Implementation
 * Manages event hooks and handlers
 */

import { nanoid } from 'nanoid';
import { createLogger } from '@kitiumai/logger';
import { HookManager, HookRegistration, HookEventType, HookContext, HookHandler } from './types';

const logger = createLogger();

/**
 * Hook Manager implementation
 */
export class HookManagerImpl implements HookManager {
  private hooks: Map<string, HookRegistration> = new Map();
  private eventHooks: Map<HookEventType, Set<string>> = new Map();

  /**
   * Register a hook handler
   */
  on<T = unknown>(event: HookEventType, handler: HookHandler<T>, priority: number = 100): string {
    const hookId = `hook_${nanoid()}`;
    const registration: HookRegistration = {
      id: hookId,
      event,
      handler: handler as HookHandler,
      priority,
      enabled: true,
    };

    this.hooks.set(hookId, registration);

    if (!this.eventHooks.has(event)) {
      this.eventHooks.set(event, new Set());
    }
    this.eventHooks.get(event)!.add(hookId);

    logger.debug('Hook registered', { hookId, event, priority });
    return hookId;
  }

  /**
   * Register a one-time hook handler
   */
  once<T = unknown>(event: HookEventType, handler: HookHandler<T>, priority: number = 100): string {
    const hookIdRef: { current: string | null } = { current: null };
    const wrappedHandler: HookHandler<T> = async (context, data) => {
      await handler(context, data);
      if (hookIdRef.current) {
        this.off(hookIdRef.current);
      }
    };

    hookIdRef.current = this.on(event, wrappedHandler, priority);
    return hookIdRef.current;
  }

  /**
   * Unregister a hook handler
   */
  off(hookId: string): void {
    const registration = this.hooks.get(hookId);
    if (!registration) {
      logger.warn('Hook not found', { hookId });
      return;
    }

    this.hooks.delete(hookId);
    const eventHooks = this.eventHooks.get(registration.event);
    if (eventHooks) {
      eventHooks.delete(hookId);
      if (eventHooks.size === 0) {
        this.eventHooks.delete(registration.event);
      }
    }

    logger.debug('Hook unregistered', { hookId, event: registration.event });
  }

  /**
   * Emit a hook event
   */
  async emit<T = unknown>(event: HookEventType, context: HookContext, data: T): Promise<void> {
    const hookIds = this.eventHooks.get(event);
    if (!hookIds || hookIds.size === 0) {
      return;
    }

    const registrations = Array.from(hookIds)
      .map((id) => this.hooks.get(id))
      .filter((reg): reg is HookRegistration => reg !== undefined && reg.enabled !== false)
      .sort((a, b) => (a.priority || 100) - (b.priority || 100));

    logger.debug('Emitting hook event', {
      event,
      handlerCount: registrations.length,
    });

    for (const registration of registrations) {
      try {
        await registration.handler(context, data);
      } catch (error) {
        logger.error('Hook handler error', {
          hookId: registration.id,
          event,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue executing other hooks even if one fails
      }
    }
  }

  /**
   * Get all registered hooks for an event
   */
  getHooks(event: HookEventType): HookRegistration[] {
    const hookIds = this.eventHooks.get(event);
    if (!hookIds) {
      return [];
    }

    return Array.from(hookIds)
      .map((id) => this.hooks.get(id))
      .filter((reg): reg is HookRegistration => reg !== undefined)
      .sort((a, b) => (a.priority || 100) - (b.priority || 100));
  }

  /**
   * Clear all hooks for an event (or all events)
   */
  clear(event?: HookEventType): void {
    if (event) {
      const hookIds = this.eventHooks.get(event);
      if (hookIds) {
        for (const hookId of hookIds) {
          this.hooks.delete(hookId);
        }
        this.eventHooks.delete(event);
      }
    } else {
      this.hooks.clear();
      this.eventHooks.clear();
    }

    logger.debug('Hooks cleared', { event });
  }
}

/**
 * Create a new hook manager instance
 */
export function createHookManager(): HookManager {
  return new HookManagerImpl();
}
