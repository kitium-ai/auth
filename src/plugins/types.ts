/**
 * Plugin system types
 */

/**
 * Plugin interface
 */
export interface Plugin {
  name: string;
  version: string;
  type: 'storage' | 'billing' | 'framework' | 'provider';
  setup: (context: PluginContext) => Promise<void>;
  teardown?: () => Promise<void>;
  hooks?: Record<string, (...args: unknown[]) => Promise<unknown> | unknown>;
}

/**
 * Plugin context
 */
export interface PluginContext {
  appName: string;
  config: Record<string, unknown>;
  logger: {
    debug: (message: string, data?: unknown) => void;
    info: (message: string, data?: unknown) => void;
    warn: (message: string, data?: unknown) => void;
    error: (message: string, data?: unknown) => void;
  };
  utils: Record<string, unknown>;
}

/**
 * Plugin manager interface
 */
export interface PluginManager {
  register(plugin: Plugin): Promise<void>;
  unregister(pluginName: string): Promise<void>;
  get(pluginName: string): Plugin | undefined;
  getAll(): Plugin[];
  executeHook(hookName: string, ...args: unknown[]): Promise<unknown>;
}
