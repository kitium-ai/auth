import express, { type Express, type Router } from 'express';
import type { Server } from 'node:http';
import { getLogger } from '@kitiumai/logger';

export interface HttpAuthServiceOptions {
  routes?: Router[];
  configure?(app: Express): void;
}

export class HttpAuthService {
  private readonly app: Express;
  private server?: Server;
  private readonly logger = getLogger();

  constructor(
    private readonly port: number,
    private readonly options: HttpAuthServiceOptions = {}
  ) {
    this.app = express();
    this.configure();
  }

  private configure(): void {
    this.app.disable('x-powered-by');
    this.app.use(express.json());

    this.app.get('/healthz', (_req, res) => {
      res.json({ status: 'ok' });
    });

    this.options.configure?.(this.app);

    if (this.options.routes) {
      for (const route of this.options.routes) {
        this.app.use(route);
      }
    }
  }

  getPort(): number {
    return this.port;
  }

  getApp(): Express {
    return this.app;
  }

  async start(): Promise<void> {
    if (this.server) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      this.server = this.app.listen(this.port, () => {
        this.logger.info('Auth HTTP service listening', { port: this.port });
        resolve();
      });
      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    if (!this.server) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      this.server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });

    this.logger.info('Auth HTTP service stopped');
    this.server = undefined;
  }
}

export async function startAuthService(
  port: number,
  options?: HttpAuthServiceOptions
): Promise<HttpAuthService> {
  const service = new HttpAuthService(port, options);
  await service.start();
  return service;
}
