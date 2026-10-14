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

  static setDemoAnalyst(): AuthUser {
    const demoUser: AuthUser = {
      id: 'analyst-guest-' + Math.floor(1000 + Math.random() * 9000),
      name: 'Guest Analyst',
      email: 'analyst.guest@scamspotter.org'
    };
    const demoSession = 'demo_session_' + Date.now();
    this.sessionId = demoSession;
    this.currentUser = demoUser;
    const storage = safeStorage();
    if (storage) {
      storage.setItem(SESSION_KEY, demoSession);
      storage.setItem(USER_KEY, JSON.stringify(demoUser));
    }
    this.notifyAuthStateChanged();
    return demoUser;
  }

  private static notifyAuthStateChanged() {
    if (typeof window !== 'undefined' && typeof window.dispatchEvent === 'function') {
      try {
        window.dispatchEvent(new CustomEvent('auth-state-changed'));
      } catch {}
    }
  }

  static async signup(name: string, email: string, password: string): Promise<AuthUser> {
    try {
      const res = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password })
      });

      let data: any = {};
      try {
        data = await res.json();
      } catch {
        throw new Error(`Server returned status ${res.status}. Please ensure backend is active.`);
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
      this.notifyAuthStateChanged();
      return data.user;
    } catch (err: any) {
      if (err.message && (err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))) {
        const localUser: AuthUser = {
          id: 'analyst-' + Math.floor(1000 + Math.random() * 9000),
          name: name || 'Analyst',
          email: email
        };
        const localSession = 'local_session_' + Date.now();
        this.sessionId = localSession;
        this.currentUser = localUser;
        const storage = safeStorage();
        if (storage) {
          storage.setItem(SESSION_KEY, localSession);
          storage.setItem(USER_KEY, JSON.stringify(localUser));
        }
        this.notifyAuthStateChanged();
        return localUser;
      }
      throw err;
    }
  }

  static async login(email: string, password: string): Promise<AuthUser> {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      let data: any = {};
      try {
        data = await res.json();
      } catch {
        throw new Error(`Server returned status ${res.status}. Please check server logs.`);
      }

      if (!res.ok) {
        throw new Error(data.error || 'Invalid credentials.');
      }

      this.sessionId = data.sessionId;
      this.currentUser = data.user;
      const storage = safeStorage();
      if (storage) {
        storage.setItem(SESSION_KEY, data.sessionId);
        storage.setItem(USER_KEY, JSON.stringify(data.user));
      }
      this.notifyAuthStateChanged();
      return data.user;
    } catch (err: any) {
      if (err.message && (err.message.includes('Failed to fetch') || err.message.includes('NetworkError'))) {
        const localUser: AuthUser = {
          id: 'analyst-local',
          name: email.split('@')[0] || 'Analyst',
          email: email
        };
        const localSession = 'local_session_' + Date.now();
        this.sessionId = localSession;
        this.currentUser = localUser;
        const storage = safeStorage();
        if (storage) {
          storage.setItem(SESSION_KEY, localSession);
          storage.setItem(USER_KEY, JSON.stringify(localUser));
        }
        this.notifyAuthStateChanged();
        return localUser;
      }
      throw err;
    }
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
