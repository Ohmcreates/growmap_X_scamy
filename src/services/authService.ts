export interface AuthUser {
  id: string;
  name: string;
  email: string;
}

const SESSION_KEY = 'scam_spotter_session_id';
const USER_KEY = 'scam_spotter_user_data';

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

    this.sessionId = storage.getItem(SESSION_KEY);
    const cachedUser = storage.getItem(USER_KEY);
    if (cachedUser) {
      try {
        this.currentUser = JSON.parse(cachedUser);
      } catch {
        this.currentUser = null;
      }
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

  static isAuthenticated(): boolean {
    return !!this.currentUser && !!this.sessionId;
  }

  static async verifySession(): Promise<AuthUser | null> {
    const session = this.getSessionId();
    if (!session) return null;

    try {
      const res = await fetch('/api/auth/me', {
        headers: { 'X-Session-ID': session }
      });
      if (!res.ok) return null;
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

  static async signup(name: string, email: string, password: string): Promise<AuthUser> {
    const res = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password })
    });
    const data = await res.json();
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
    return data.user;
  }

  static async login(email: string, password: string): Promise<AuthUser> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Login failed.');
    }

    this.sessionId = data.sessionId;
    this.currentUser = data.user;
    const storage = safeStorage();
    if (storage) {
      storage.setItem(SESSION_KEY, data.sessionId);
      storage.setItem(USER_KEY, JSON.stringify(data.user));
    }
    return data.user;
  }

  static async logout(): Promise<void> {
    const session = this.getSessionId();
    if (session) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'X-Session-ID': session }
        });
      } catch {}
    }
    this.clearSession();
  }

  private static clearSession() {
    this.sessionId = null;
    this.currentUser = null;
    const storage = safeStorage();
    if (storage) {
      storage.removeItem(SESSION_KEY);
      storage.removeItem(USER_KEY);
    }
  }
}

AuthService.init();
