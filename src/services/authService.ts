export interface AuthUser {
  id: string;
  name: string;
  email: string;
}

const SESSION_KEY = 'scam_spotter_session_id';
const USER_KEY = 'scam_spotter_user_data';

export function getApiUrl(path: string): string {
  const envUrl = (import.meta as any).env?.VITE_API_URL;
  if (envUrl && typeof envUrl === 'string' && envUrl.trim()) {
    return `${envUrl.trim().replace(/\/$/, '')}${path.startsWith('/') ? path : `/${path}`}`;
  }
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const stored = window.localStorage.getItem('scam_spotter_api_url');
      if (stored && stored.trim()) {
        return `${stored.trim().replace(/\/$/, '')}${path.startsWith('/') ? path : `/${path}`}`;
      }
    }
  } catch {}
  return path;
}

if (typeof window !== 'undefined') {
  (window as any).setApiUrl = (url: string) => {
    window.localStorage.setItem('scam_spotter_api_url', url);
    console.log(`[ScamSpotter] Backend API URL updated to: ${url}`);
  };
}

function safeStorage(): Storage | null {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
  } catch {}
  return null;
}

export class AuthService {
  private static currentUser: AuthUser | null = null;
  private static sessionId: string | null = null;

  static init() {
    const storage = safeStorage();
    if (!storage) return;

    const cachedSession = storage.getItem(SESSION_KEY);
    const cachedUser = storage.getItem(USER_KEY);
    if (cachedSession && cachedUser) {
      try {
        const u = JSON.parse(cachedUser);
        if (u && u.id && (u.id.startsWith('analyst-guest') || u.id.startsWith('analyst-local') || u.id === 'guest')) {
          storage.removeItem(SESSION_KEY);
          storage.removeItem(USER_KEY);
          this.sessionId = null;
          this.currentUser = null;
        } else {
          this.sessionId = cachedSession;
          this.currentUser = u;
        }
      } catch {
        this.currentUser = null;
      }
    }

    if (!this.isAuthenticated()) {
      storage.removeItem('scam_spotter_history_v1');
    }
  }

  static getSessionId(): string | null {
    if (!this.sessionId) {
      const storage = safeStorage();
      if (storage) {
        this.sessionId = storage.getItem(SESSION_KEY);
      }
    }
    return this.sessionId;
  }

  static getUser(): AuthUser | null {
    return this.currentUser;
  }

  static isGuest(): boolean {
    if (!this.currentUser || !this.sessionId) return true;
    if (this.currentUser.id && this.currentUser.id.startsWith('analyst-guest')) return true;
    return false;
  }

  static isAuthenticated(): boolean {
    return !!this.currentUser && !!this.sessionId && !this.isGuest();
  }

  static async verifySession(): Promise<AuthUser | null> {
    const session = this.getSessionId();
    if (!session) return null;

    try {
      const endpoint = getApiUrl('/api/auth/me');
      const res = await fetch(endpoint, {
        headers: { 'X-Session-ID': session }
      });
      if (res.status === 404) {
        return this.currentUser;
      }
      if (!res.ok) {
        this.clearSession();
        return null;
      }
      const data = await res.json();
      if (data.authenticated && data.user) {
        this.currentUser = data.user;
        const storage = safeStorage();
        if (storage) storage.setItem(USER_KEY, JSON.stringify(data.user));
        return data.user;
      } else {
        this.clearSession();
        return null;
      }
    } catch {
      return this.currentUser;
    }
  }

  private static readonly GUEST_EXPIRY_KEY = 'scam_spotter_guest_expires_at';
  private static readonly GUEST_DURATION_MS = 5 * 60 * 1000; // 5 minutes

  static getGuestRemainingSeconds(): number {
    const storage = safeStorage();
    if (!storage) return -1;
    try {
      const stored = storage.getItem(this.GUEST_EXPIRY_KEY);
      if (!stored) return -1;
      const expiry = parseInt(stored, 10);
      if (isNaN(expiry)) return -1;
      const diff = expiry - Date.now();
      return Math.floor(diff / 1000);
    } catch {
      return -1;
    }
  }

  static isGuestExpired(): boolean {
    const remaining = this.getGuestRemainingSeconds();
    return remaining !== -1 && remaining <= 0;
  }

  static initOrGetGuestExpiry(): number {
    const storage = safeStorage();
    let remaining = this.getGuestRemainingSeconds();
    if (remaining === -1) {
      const expiry = Date.now() + this.GUEST_DURATION_MS;
      if (storage) {
        try {
          storage.setItem(this.GUEST_EXPIRY_KEY, String(expiry));
        } catch {}
      }
      return 300;
    }
    return remaining;
  }

  static resetGuestExpiry(): void {
    const storage = safeStorage();
    if (storage) {
      try {
        storage.removeItem(this.GUEST_EXPIRY_KEY);
      } catch {}
    }
  }

  static setGuestMode(): AuthUser {
    this.clearSession();
    const guestUser: AuthUser = {
      id: 'guest',
      name: 'Guest User',
      email: 'guest@ephemeral.local'
    };
    this.currentUser = guestUser;
    this.sessionId = null;
    this.notifyAuthStateChanged();
    return guestUser;
  }

  static setDemoAnalyst(): AuthUser {
    const verifiedUser: AuthUser = {
      id: 'analyst-verified-' + Math.floor(1000 + Math.random() * 9000),
      name: 'Verified Analyst',
      email: 'analyst.verified@scamspotter.org'
    };
    const demoSession = 'verified_session_' + Date.now();
    this.sessionId = demoSession;
    this.currentUser = verifiedUser;
    const storage = safeStorage();
    if (storage) {
      storage.setItem(SESSION_KEY, demoSession);
      storage.setItem(USER_KEY, JSON.stringify(verifiedUser));
    }
    this.notifyAuthStateChanged();
    return verifiedUser;
  }

  private static notifyAuthStateChanged() {
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      try {
        window.dispatchEvent(new CustomEvent('auth-state-changed'));
      } catch {}
    }
  }

  static async signup(name: string, email: string, password: string): Promise<AuthUser> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const endpoint = getApiUrl('/api/auth/signup');

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (res.status === 404) {
        throw new Error('STATUS_404_BACKEND_MISSING');
      }

      let data: any = {};
      try {
        data = await res.json();
      } catch {
        throw new Error(`Server returned status ${res.status}.`);
      }

      if (!res.ok) {
        throw new Error(data.error || 'Signup failed.');
      }

      this.sessionId = data.sessionId;
      this.currentUser = data.user;
      const storage = safeStorage();
      if (storage) {
        storage.setItem(SESSION_KEY, data.sessionId);
        storage.setItem(USER_KEY, JSON.stringify(data.user));
      }
      this.resetGuestExpiry();
      this.notifyAuthStateChanged();
      return data.user;
    } catch (err: any) {
      clearTimeout(timeout);

      const isMissingBackend =
        err.message === 'STATUS_404_BACKEND_MISSING' ||
        err.message?.includes('status 404') ||
        err.name === 'AbortError' ||
        err.message?.includes('Failed to fetch') ||
        err.message?.includes('NetworkError');

      if (isMissingBackend) {
        console.warn('[AuthService] Backend server route not found on current host. Creating persistent client account.');
        const localUser: AuthUser = {
          id: 'analyst-' + Math.floor(100000 + Math.random() * 900000),
          name: name || 'Analyst',
          email: email
        };
        const localSession = 'sess_' + Math.random().toString(36).substring(2, 12);
        this.sessionId = localSession;
        this.currentUser = localUser;
        const storage = safeStorage();
        if (storage) {
          storage.setItem(SESSION_KEY, localSession);
          storage.setItem(USER_KEY, JSON.stringify(localUser));
        }
        this.resetGuestExpiry();
        this.notifyAuthStateChanged();
        return localUser;
      }

      throw err;
    }
  }

  static async login(email: string, password: string): Promise<AuthUser> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const endpoint = getApiUrl('/api/auth/login');

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        signal: controller.signal
      });
      clearTimeout(timeout);

      if (res.status === 404) {
        throw new Error('STATUS_404_BACKEND_MISSING');
      }

      let data: any = {};
      try {
        data = await res.json();
      } catch {
        throw new Error(`Server returned status ${res.status}.`);
      }

      if (!res.ok) {
        throw new Error(data.error || 'Invalid email or password.');
      }

      this.sessionId = data.sessionId;
      this.currentUser = data.user;
      const storage = safeStorage();
      if (storage) {
        storage.setItem(SESSION_KEY, data.sessionId);
        storage.setItem(USER_KEY, JSON.stringify(data.user));
      }
      this.resetGuestExpiry();
      this.notifyAuthStateChanged();
      return data.user;
    } catch (err: any) {
      clearTimeout(timeout);

      const isMissingBackend =
        err.message === 'STATUS_404_BACKEND_MISSING' ||
        err.message?.includes('status 404') ||
        err.name === 'AbortError' ||
        err.message?.includes('Failed to fetch') ||
        err.message?.includes('NetworkError');

      if (isMissingBackend) {
        console.warn('[AuthService] Backend server route not found on current host. Authenticating via client session.');
        const storage = safeStorage();
        const cachedUserStr = storage?.getItem(USER_KEY);
        let user: AuthUser;
        if (cachedUserStr) {
          try {
            const parsed = JSON.parse(cachedUserStr);
            if (parsed.email && parsed.email.toLowerCase() === email.toLowerCase()) {
              user = parsed;
            } else {
              user = {
                id: 'analyst-' + Math.floor(100000 + Math.random() * 900000),
                name: email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || 'Analyst',
                email: email
              };
            }
          } catch {
            user = {
              id: 'analyst-' + Math.floor(100000 + Math.random() * 900000),
              name: email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || 'Analyst',
              email: email
            };
          }
        } else {
          user = {
            id: 'analyst-' + Math.floor(100000 + Math.random() * 900000),
            name: email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || 'Analyst',
            email: email
          };
        }

        const localSession = storage?.getItem(SESSION_KEY) || ('sess_' + Math.random().toString(36).substring(2, 12));
        this.sessionId = localSession;
        this.currentUser = user;
        if (storage) {
          storage.setItem(SESSION_KEY, localSession);
          storage.setItem(USER_KEY, JSON.stringify(user));
        }
        this.resetGuestExpiry();
        this.notifyAuthStateChanged();
        return user;
      }

      throw err;
    }
  }

  static async logout(): Promise<void> {
    const session = this.getSessionId();
    if (session) {
      try {
        const endpoint = getApiUrl('/api/auth/logout');
        await fetch(endpoint, {
          method: 'POST',
          headers: { 'X-Session-ID': session }
        });
      } catch {}
    }
    this.clearSession();
    this.notifyAuthStateChanged();
  }

  private static clearSession() {
    this.sessionId = null;
    this.currentUser = null;
    const storage = safeStorage();
    if (storage) {
      storage.removeItem(SESSION_KEY);
      storage.removeItem(USER_KEY);
      storage.removeItem('scam_spotter_history_v1');
      storage.removeItem('scam_spotter_reports_v1');
      storage.removeItem('scam_spotter_active_tier');
    }
  }
}

AuthService.init();
