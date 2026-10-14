import { beforeEach, describe, expect, it } from 'vitest';
import { analyzeMessage } from '../../engine/scorer.js';
import { HistoryService } from '../history.js';
import { AuthService } from '../authService.js';

describe('Scam Spotter — Phase 6 Private Scan History & Retention', () => {
  // Mock localStorage for node environment
  const mockStorage = new Map<string, string>();

  beforeEach(() => {
    mockStorage.clear();
    // Setup global window and localStorage mock
    (globalThis as any).window = {
      localStorage: {
        getItem: (key: string) => mockStorage.get(key) || null,
        setItem: (key: string, val: string) => mockStorage.set(key, val),
        removeItem: (key: string) => mockStorage.delete(key),
      },
    };
    AuthService.setDemoAnalyst();
  });

  it('masks phone numbers and card digits in stored preview for privacy', () => {
    const raw = 'Call +919876543210 regarding card 4111 2222 3333 4444 block';
    const res = analyzeMessage(raw);

    const saved = HistoryService.saveScan(raw, res);
    expect(saved).not.toBeNull();
    expect(saved?.preview).not.toContain('4111 2222 3333 4444');
    expect(saved?.preview).toContain('[MASKED]');
  });

  it('caps history at exactly 50 entries and evicts oldest items FIFO', () => {
    const res = analyzeMessage('Test message');

    for (let i = 0; i < 55; i++) {
      HistoryService.saveScan(`Message index ${i}`, res);
    }

    const history = HistoryService.getHistory();
    expect(history.length).toBe(50);
    // Latest item (index 54) is at the top
    expect(history[0].preview).toContain('Message index 54');
  });

  it('does NOT save scans or history when user is unauthenticated guest', () => {
    (AuthService as any).clearSession();
    const res = analyzeMessage('Guest test message');
    const saved = HistoryService.saveScan('Guest test message', res);
    expect(saved).toBeNull();
    expect(HistoryService.getHistory().length).toBe(0);
  });

  it('gracefully handles storage quota exceptions without crashing scan execution', () => {
    (globalThis as any).window.localStorage.setItem = () => {
      throw new Error('QuotaExceededError');
    };

    const res = analyzeMessage('Test message');
    expect(() => {
      HistoryService.saveScan('Test message', res);
    }).not.toThrow();
  });
});
