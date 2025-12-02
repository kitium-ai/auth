/**
 * React framework integration for authentication
 * NOTE: Requires React as a peer dependency and @kitiumai/utils-react for hooks
 */

export type User = {
  id: string;
  email: string;
  name?: string;
};

export type AuthError = {
  code: string;
  message: string;
};

/**
 * Note: useAuth and useAuthToken hooks should be implemented using
 * @kitiumai/utils-react hooks in your application code.
 *
 * Example with useAsync from @kitiumai/utils-react/hooks/async:
 *   import { useAsync } from '@kitiumai/utils-react/hooks/async';
 *
 *   export function useAuthHook() {
 *     return useAsync(() => fetchUser(), []);
 *   }
 */
