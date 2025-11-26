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
  hooks?: Record<string, Function>;
}

/**
 * Plugin context
 */
export interface PluginContext {
  appName: string;
  config: Record<string, unknown>;
  logger: any;
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
