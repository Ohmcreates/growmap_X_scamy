export type IndicatorType = 'DOMAIN' | 'PHONE' | 'UPI_ID';
export type IndicatorStatus = 'REPORTED' | 'UNDER_REVIEW' | 'VERIFIED' | 'EXPIRED';

export interface ThreatReport {
  id: string;
  type: IndicatorType;
  rawValue: string;
  normalizedValue: string;
  category: string;
  notes?: string;
  reportedAt: string;
}

export interface VerifiedIndicator {
  type: IndicatorType;
  normalizedValue: string;
  status: IndicatorStatus;
  threatLevel: 'HIGH' | 'CRITICAL';
  source: string;
  verifiedAt: string;
}

const REPORT_STORAGE_KEY = 'scam_spotter_reports_v1';

export class ReportingService {
  static normalizeIndicator(type: IndicatorType, value: string): string {
    const trimmed = value.trim().toLowerCase();
    if (type === 'DOMAIN') {
      try {
        const urlStr = trimmed.startsWith('http') ? trimmed : `http://${trimmed}`;
        return new URL(urlStr).hostname.replace(/^www\./, '');
      } catch {
        return trimmed.replace(/^https?:\/\//, '').split('/')[0].replace(/^www\./, '');
      }
    }
    if (type === 'PHONE') {
      const digits = trimmed.replace(/\D/g, '');
      if (digits.length === 10) return `+91${digits}`;
      if (digits.length === 12 && digits.startsWith('91')) return `+${digits}`;
      return `+${digits}`;
    }
    if (type === 'UPI_ID') {
      return trimmed.replace(/\s+/g, '');
    }
    return trimmed;
  }

  private static rateLimitMap = new Map<string, number[]>();

  static checkRateLimit(clientId: string, maxPerMinute = 5): boolean {
    const now = Date.now();
    const timestamps = (this.rateLimitMap.get(clientId) || []).filter((t) => now - t < 60000);
    if (timestamps.length >= maxPerMinute) {
      return false; // Rate limit exceeded
    }
    timestamps.push(now);
    this.rateLimitMap.set(clientId, timestamps);
    return true;
  }

  static transitionIndicatorState(
    current: IndicatorStatus,
    target: IndicatorStatus
  ): { allowed: boolean; newStatus: IndicatorStatus; error?: string } {
    const validTransitions: Record<IndicatorStatus, IndicatorStatus[]> = {
      REPORTED: ['UNDER_REVIEW'],
      UNDER_REVIEW: ['VERIFIED', 'EXPIRED'],
      VERIFIED: ['EXPIRED'],
      EXPIRED: [],
    };

    if (validTransitions[current]?.includes(target)) {
      return { allowed: true, newStatus: target };
    }

    return {
      allowed: false,
      newStatus: current,
      error: `Invalid transition from ${current} to ${target}`,
    };
  }

  static submitReport(
    type: IndicatorType,
    rawValue: string,
    category: string,
    notes?: string,
    clientId = 'default_client'
  ): ThreatReport {
    if (!this.checkRateLimit(clientId)) {
      throw new Error('RATE_LIMIT_EXCEEDED: Maximum 5 reports per minute reached.');
    }

    const normalizedValue = this.normalizeIndicator(type, rawValue);
    const report: ThreatReport = {
      id: `rep_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      type,
      rawValue,
      normalizedValue,
      category,
      notes,
      reportedAt: new Date().toISOString(),
    };

    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        const stored = window.localStorage.getItem(REPORT_STORAGE_KEY);
        const list: ThreatReport[] = stored ? JSON.parse(stored) : [];
        list.unshift(report);
        if (list.length > 30) list.length = 30;
        window.localStorage.setItem(REPORT_STORAGE_KEY, JSON.stringify(list));
      }
    } catch (e) {
      console.warn('Could not persist threat report:', e);
    }

    return report;
  }

  static getKnownBadIndicators(): VerifiedIndicator[] {
    return [
      {
        type: 'DOMAIN',
        normalizedValue: 'sbi-kyc-update.xyz',
        status: 'VERIFIED',
        threatLevel: 'CRITICAL',
        source: 'Simulated National Phishing Blacklist',
        verifiedAt: '2026-10-10T00:00:00Z',
      },
      {
        type: 'DOMAIN',
        normalizedValue: 'hdfc-reward-points.top',
        status: 'VERIFIED',
        threatLevel: 'CRITICAL',
        source: 'Verified Threat Feed',
        verifiedAt: '2026-10-11T00:00:00Z',
      },
      {
        type: 'DOMAIN',
        normalizedValue: 'mparivahan.redirectme.net',
        status: 'VERIFIED',
        threatLevel: 'CRITICAL',
        source: 'National Cybercrime Threat Feed (E-Challan / MoRTH Phishing)',
        verifiedAt: '2026-10-13T00:00:00Z',
      },
      {
        type: 'DOMAIN',
        normalizedValue: 'redirectme.net',
        status: 'VERIFIED',
        threatLevel: 'HIGH',
        source: 'Dynamic DNS Phishing Shield',
        verifiedAt: '2026-10-13T00:00:00Z',
      },
    ];
  }
}
