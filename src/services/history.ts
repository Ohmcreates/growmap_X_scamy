import { RiskLevel, ScanResult } from '../engine/types.js';

export interface HistoryItem {
  id: string;
  createdAt: string;
  score: number;
  riskLevel: RiskLevel;
  ruleIds: string[];
  preview: string;
  fullText?: string;
  scamProfileName?: string;
}

const STORAGE_KEY = 'scam_spotter_history_v1';
const MAX_HISTORY_ITEMS = 50;

function maskSensitiveDigits(text: string): string {
  // Mask 10-digit mobile numbers or 12-16 digit account/card numbers
  return text.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{2,8}\b/g, '[MASKED]');
}

export class HistoryService {
  private static isAvailable(): boolean {
    try {
      if (typeof window === 'undefined' || !window.localStorage) return false;
      const testKey = '__storage_test__';
      window.localStorage.setItem(testKey, '1');
      window.localStorage.removeItem(testKey);
      return true;
    } catch {
      return false;
    }
  }

  static getHistory(): HistoryItem[] {
    if (!this.isAvailable()) return [];
    try {
      const data = window.localStorage.getItem(STORAGE_KEY);
      if (!data) return [];
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.warn('Failed to read scan history from storage:', e);
      return [];
    }
  }

  static saveScan(
    rawText: string,
    result: ScanResult,
    saveFullText = false
  ): HistoryItem | null {
    if (!this.isAvailable()) return null;

    try {
      const history = this.getHistory();
      const maskedText = maskSensitiveDigits(rawText.trim());
      const preview = maskedText.length > 60 ? `${maskedText.slice(0, 60)}...` : maskedText;

      const newItem: HistoryItem = {
        id: `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
        createdAt: new Date().toISOString(),
        score: result.score,
        riskLevel: result.riskLevel,
        ruleIds: result.breakdown.map((b) => b.ruleId),
        preview,
        fullText: saveFullText ? rawText : undefined,
        scamProfileName: result.scamProfile?.name,
      };

      // Add to front of history list
      history.unshift(newItem);

      // Enforce 50-item limit
      if (history.length > MAX_HISTORY_ITEMS) {
        history.length = MAX_HISTORY_ITEMS;
      }

      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
      return newItem;
    } catch (e) {
      console.warn('Failed to save scan to storage:', e);
      return null;
    }
  }

  static deleteItem(id: string): boolean {
    if (!this.isAvailable()) return false;
    try {
      const history = this.getHistory().filter((item) => item.id !== id);
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
      return true;
    } catch {
      return false;
    }
  }

  static clearHistory(): boolean {
    if (!this.isAvailable()) return false;
    try {
      window.localStorage.removeItem(STORAGE_KEY);
      return true;
    } catch {
      return false;
    }
  }
}
