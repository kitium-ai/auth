/**
 * Lazy loading system
 * Dynamically load modules on demand to reduce bundle size
 */

import { createLogger } from '@kitiumai/logger';

const logger = createLogger();

/**
 * Lazy loader for managing dynamic imports
 */
class LazyLoader {
  private readonly loaded = new Map<string, unknown>();
  private readonly loading = new Map<string, Promise<unknown>>();

  /**
   * Load a module asynchronously
   */
  async load<T = unknown>(moduleName: string): Promise<T> {
    // Return cached module if already loaded
    if (this.loaded.has(moduleName)) {
      return this.loaded.get(moduleName) as T;
    }

    // Return existing promise if currently loading
    if (this.loading.has(moduleName)) {
      return this.loading.get(moduleName) as Promise<T>;
    }

    // Start loading
    const loadPromise = this.loadModule<T>(moduleName);
    this.loading.set(moduleName, loadPromise);

    try {
      const module = await loadPromise;
      this.loaded.set(moduleName, module);
      this.loading.delete(moduleName);
      return module;
    } catch (error) {
      this.loading.delete(moduleName);
      logger.error(`Failed to load module ${moduleName}`, { error: String(error) });
      throw error;
    }
  }

  /**
   * Preload a module
   */
  async preload(moduleName: string): Promise<void> {
    try {
      await this.load(moduleName);
      logger.debug(`Preloaded module ${moduleName}`);
    } catch (error) {
      logger.warn(`Failed to preload module ${moduleName}`, { error: String(error) });
    }
  }

  /**
   * Clear cache for a specific module
   */
  clear(moduleName?: string): void {
    if (moduleName) {
      this.loaded.delete(moduleName);
    } else {
      this.loaded.clear();
    }
  }

  /**
   * Get loaded modules
   */
  getLoaded(): string[] {
    return Array.from(this.loaded.keys());
  }

  /**
   * Internal method to load module
   */
  private async loadModule<T = unknown>(moduleName: string): Promise<T> {
    logger.debug(`Loading module ${moduleName}`);
    // Use native dynamic import so consumers receive the actual module exports.
    const loadedModule = await import(moduleName);
    return loadedModule as T;
  }
}

// Create singleton instance
export const lazyLoader = new LazyLoader();

/**
 * Lazy import helper
 */
export async function lazy<T = unknown>(moduleName: string): Promise<T> {
  return lazyLoader.load<T>(moduleName);
}

/**
 * Lazy import (alias for lazy)
 */
export async function lazyImport<T = unknown>(moduleName: string): Promise<T> {
  return lazyLoader.load<T>(moduleName);
}

/**
 * Load if available (doesn't throw on error)
 */
export async function loadIfAvailable<T = unknown>(
  moduleName: string,
  fallback?: T
): Promise<T | undefined> {
  try {
    return await lazyLoader.load<T>(moduleName);
  } catch {
    return fallback;
  }
}
