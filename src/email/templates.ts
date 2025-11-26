/**
 * Email templates
 */

export function createPasswordResetTemplate(link: string): string {
  return `<a href="${link}">Reset Password</a>`;
}

export function createEmailVerificationTemplate(link: string): string {
  return `<a href="${link}">Verify Email</a>`;
}

export function createVerificationCodeTemplate(code: string): string {
  return `<p>Your code: ${code}</p>`;
}

export function createLoginLinkTemplate(link: string): string {
  return `<a href="${link}">Login</a>`;
}

export function createWelcomeTemplate(name: string): string {
  return `<p>Welcome, ${name}!</p>`;
}
