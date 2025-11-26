/**
 * Plugin Manager
 * Manages registration and lifecycle of auth plugins
 */

import { getLogger } from '@kitiumai/logger';
import { Plugin, PluginContext, PluginManager } from './types';

/**
 * KitiumPluginManager implementation
 */
export class KitiumPluginManager implements PluginManager {
  private plugins = new Map<string, Plugin>();
  private logger = getLogger();

  /**
   * Register a plugin
   */
  async register(plugin: Plugin): Promise<void> {
    if (this.plugins.has(plugin.name)) {
      this.logger.warn(`Plugin ${plugin.name} is already registered`);
      return;
    }

    try {
      const context: PluginContext = {
        appName: 'KitiumAuth',
        config: {},
        logger: this.logger,
        utils: {},
      };

      await plugin.setup(context);
      this.plugins.set(plugin.name, plugin);
      this.logger.info(`Plugin ${plugin.name} registered successfully`);
    } catch (error) {
      this.logger.error(`Failed to register plugin ${plugin.name}`, {
        error: String(error),
      });
      throw error;
    }
  }

  /**
   * Unregister a plugin
   */
  async unregister(pluginName: string): Promise<void> {
    const plugin = this.plugins.get(pluginName);

    if (!plugin) {
      this.logger.warn(`Plugin ${pluginName} not found`);
      return;
    }

    try {
      if (plugin.teardown) {
        await plugin.teardown();
      }

      this.plugins.delete(pluginName);
      this.logger.info(`Plugin ${pluginName} unregistered successfully`);
    } catch (error) {
      this.logger.error(`Failed to unregister plugin ${pluginName}`, {
        error: String(error),
      });
      throw error;
    }
  }

  /**
   * Get plugin by name
   */
  get(pluginName: string): Plugin | undefined {
    return this.plugins.get(pluginName);
  }

  /**
   * Get all plugins
   */
  getAll(): Plugin[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Execute hook across all plugins
   */
  async executeHook(hookName: string, ...args: unknown[]): Promise<unknown> {
    const results: unknown[] = [];

    for (const plugin of this.plugins.values()) {
      if (plugin.hooks && typeof plugin.hooks[hookName] === 'function') {
        try {
          const result = await plugin.hooks[hookName](...args);
          results.push(result);
        } catch (error) {
          this.logger.warn(`Hook ${hookName} failed in plugin ${plugin.name}`, {
            error: String(error),
          });
        }
      }
    }

    return results;
  }
}
