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

  static submitReport(
    type: IndicatorType,
    rawValue: string,
    category: string,
    notes?: string
  ): ThreatReport {
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
    ];
  }
}
