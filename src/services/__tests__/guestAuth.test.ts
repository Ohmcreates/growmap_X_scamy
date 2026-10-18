import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { AuthService } from '../authService.js';

describe('AuthService — Unlimited Guest Mode (Timer Removed)', () => {
  let mockStorage: Map<string, string>;

  beforeEach(() => {
    mockStorage = new Map<string, string>();
    (globalThis as any).window = {
      localStorage: {
        getItem: (key: string) => mockStorage.get(key) || null,
        setItem: (key: string, val: string) => mockStorage.set(key, val),
        removeItem: (key: string) => mockStorage.delete(key),
      },
    };
    AuthService.resetGuestExpiry();
    AuthService.setGuestMode();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('allows unlimited guest usage without timer expiration', () => {
    expect(AuthService.isGuestExpired()).toBe(false);
    expect(AuthService.getGuestRemainingSeconds()).toBe(-1);
  });

  it('remains unexpired even after long periods of time', () => {
    const startTime = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(startTime + 24 * 60 * 60 * 1000); // 24 hours later
    expect(AuthService.isGuestExpired()).toBe(false);
  });
});
