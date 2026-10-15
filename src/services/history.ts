import { RiskLevel, ScanResult } from '../engine/types.js';
import { AuthService } from './authService.js';

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

  static getLocalHistory(): HistoryItem[] {
    if (!AuthService.isAuthenticated() || !this.isAvailable()) return [];
    try {
      const data = window.localStorage.getItem(STORAGE_KEY);
      if (!data) return [];
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  static getHistory(): HistoryItem[] {
    return this.getLocalHistory();
  }

  static async fetchServerHistory(): Promise<HistoryItem[]> {
    if (!AuthService.isAuthenticated()) {
      return [];
    }

    const session = AuthService.getSessionId();
    if (!session) {
      return this.getLocalHistory();
    }

    try {
      const res = await fetch('/api/scans', {
        headers: { 'X-Session-ID': session }
      });
      if (!res.ok) return this.getLocalHistory();

      const data = await res.json();
      const rows = data.history || [];

      const serverItems: HistoryItem[] = rows.map((r: any) => ({
        id: r.id,
        createdAt: r.created_at || new Date().toISOString(),
        score: r.risk_score,
        riskLevel: r.risk_level as RiskLevel,
        ruleIds: Array.isArray(r.rules_fired_json) ? r.rules_fired_json : [],
        preview: r.content_preview,
        scamProfileName: r.headline
      }));

      if (serverItems.length > 0 && this.isAvailable()) {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(serverItems.slice(0, MAX_HISTORY_ITEMS)));
      }

      return serverItems.length > 0 ? serverItems : this.getLocalHistory();
    } catch {
      return this.getLocalHistory();
    }
  }

  static saveScan(
    rawText: string,
    result: ScanResult,
    saveFullText = false
  ): HistoryItem | null {
    // Strict Privacy & Security:
    // If not authenticated (Guest), do NOT store to localStorage and do NOT send to server.
    if (!AuthService.isAuthenticated()) {
      return null;
    }

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

    if (this.isAvailable()) {
      try {
        const history = this.getLocalHistory();
        history.unshift(newItem);
        if (history.length > MAX_HISTORY_ITEMS) {
          history.length = MAX_HISTORY_ITEMS;
        }
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
      } catch {}
    }

    const session = AuthService.getSessionId();
    fetch('/api/scans', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(session ? { 'X-Session-ID': session } : {})
      },
      body: JSON.stringify({
        content: preview,
        riskScore: result.score,
        riskLevel: result.riskLevel,
        scanType: 'TEXT_MESSAGE',
        headline: result.headline || result.scamProfile?.name || 'Message Scan',
        rulesFired: result.breakdown.map((b) => b.ruleId)
      })
    }).catch(() => {});

    return newItem;
  }

  static deleteItem(id: string): boolean {
    if (!this.isAvailable()) return false;
    try {
      const history = this.getLocalHistory().filter((item) => item.id !== id);
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
