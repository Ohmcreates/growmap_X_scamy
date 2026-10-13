import { describe, expect, it } from 'vitest';
import { computeDashboardMetrics } from '../../ui/dashboard.js';
import { HistoryItem } from '../history.js';

describe('Scam Spotter — Phase 1 Feature 6: Dashboard & Repeat Indicator Analytics', () => {
  it('returns zeroes and empty lists when scan history is empty', () => {
    const metrics = computeDashboardMetrics([]);
    expect(metrics.totalScans).toBe(0);
    expect(metrics.highCount).toBe(0);
    expect(metrics.topRules).toEqual([]);
  });

  it('aggregates risk levels and calculates accurate percentages', () => {
    const mockHistory: HistoryItem[] = [
      {
        id: '1',
        createdAt: new Date().toISOString(),
        score: 100,
        riskLevel: 'HIGH',
        ruleIds: ['OTP_REQUEST', 'URGENCY'],
        preview: 'Account blocked update KYC at http://sbi-fake.xyz',
      },
      {
        id: '2',
        createdAt: new Date().toISOString(),
        score: 75,
        riskLevel: 'HIGH',
        ruleIds: ['OTP_REQUEST'],
        preview: 'Share OTP immediately',
      },
      {
        id: '3',
        createdAt: new Date().toISOString(),
        score: 45,
        riskLevel: 'MEDIUM',
        ruleIds: ['URGENCY'],
        preview: 'Delivery fee pending',
      },
      {
        id: '4',
        createdAt: new Date().toISOString(),
        score: 0,
        riskLevel: 'LOW',
        ruleIds: [],
        preview: 'Lunch at 1pm',
      },
    ];

    const metrics = computeDashboardMetrics(mockHistory);

    expect(metrics.totalScans).toBe(4);
    expect(metrics.highCount).toBe(2);
    expect(metrics.mediumCount).toBe(1);
    expect(metrics.lowCount).toBe(1);
    expect(metrics.highPercent).toBe(50);
    expect(metrics.mediumPercent).toBe(25);
    expect(metrics.lowPercent).toBe(25);

    // OTP_REQUEST appeared twice, URGENCY appeared twice
    expect(metrics.topRules.length).toBeGreaterThanOrEqual(2);
    expect(metrics.topRules[0].count).toBe(2);
  });

  it('detects repeat indicators across multiple scans for REPEAT_INDICATOR warning', () => {
    const historyWithRepeats: HistoryItem[] = [
      {
        id: '1',
        createdAt: new Date().toISOString(),
        score: 100,
        riskLevel: 'HIGH',
        ruleIds: ['SUSPICIOUS_LINK'],
        preview: 'Phishing domain sbi-fake.xyz sent to user A',
      },
      {
        id: '2',
        createdAt: new Date().toISOString(),
        score: 100,
        riskLevel: 'HIGH',
        ruleIds: ['SUSPICIOUS_LINK'],
        preview: 'Another message containing sbi-fake.xyz seen again',
      },
    ];

    const metrics = computeDashboardMetrics(historyWithRepeats);
    expect(metrics.repeatIndicators.length).toBeGreaterThan(0);
    expect(metrics.repeatIndicators[0].term).toBe('sbi-fake.xyz');
    expect(metrics.repeatIndicators[0].count).toBe(2);
  });
});
