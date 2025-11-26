/* eslint-disable no-restricted-imports */
/* eslint-disable @typescript-eslint/naming-convention */
import {
  createEmailRouteController,
  EmailRouteControllerOptions,
  EmailRegistrationRequest,
  EmailLoginRequest,
  EmailResetRequest,
  EmailPasswordResetRequest,
  EmailMagicLinkRequest,
} from '../email/routes';

export type NextEmailRouteHandler = (request: Request) => Promise<Response>;
export type EmailAuthRoutesConfig = EmailRouteControllerOptions;

const JSON_HEADERS = {
  'Content-Type': 'application/json',
};

export function createRegisterRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const payload = (await request.json()) as EmailRegistrationRequest;
    const result = await controller.register(payload);
    return jsonResponse(result, 201);
  };
}

export function createLoginRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const payload = (await request.json()) as EmailLoginRequest;
    const result = await controller.login(payload);
    return jsonResponse(result, 200);
  };
}

export function createForgotPasswordRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const payload = (await request.json()) as EmailResetRequest;
    const result = await controller.requestPasswordReset(payload);
    return jsonResponse(result, 200);
  };
}

export function createResetPasswordRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const payload = (await request.json()) as EmailPasswordResetRequest;
    const result = await controller.resetPassword(payload);
    return jsonResponse(result, 200);
  };
}

export function createMagicLinkRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const payload = (await request.json()) as EmailMagicLinkRequest;
    const result = await controller.sendMagicLink(payload);
    return jsonResponse(result, 200);
  };
}

export function createVerifyRoute(config: EmailAuthRoutesConfig): NextEmailRouteHandler {
  const controller = createEmailRouteController(config);
  return async (request) => {
    const url = new URL(request.url);
    const token = url.searchParams.get('token') || '';
    const result = await controller.verifyToken(token);
    return jsonResponse({ verified: true, email: result.email }, 200);
  };
}

export async function createEmailAuthRoutes(config: EmailAuthRoutesConfig): Promise<{
  register: NextEmailRouteHandler;
  login: NextEmailRouteHandler;
  forgotPassword: NextEmailRouteHandler;
  resetPassword: NextEmailRouteHandler;
  magicLink: NextEmailRouteHandler;
  verify: NextEmailRouteHandler;
}> {
  return {
    register: createRegisterRoute(config),
    login: createLoginRoute(config),
    forgotPassword: createForgotPasswordRoute(config),
    resetPassword: createResetPasswordRoute(config),
    magicLink: createMagicLinkRoute(config),
    verify: createVerifyRoute(config),
  };
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
}
