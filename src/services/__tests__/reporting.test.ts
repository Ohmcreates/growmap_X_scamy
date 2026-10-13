import { describe, expect, it } from 'vitest';
import { ReportingService } from '../reporting.js';

describe('Scam Spotter — Phase 7 Community Threat Graph & Rate Limiting', () => {
  it('normalizes domains, phone numbers, and UPI IDs into canonical form', () => {
    expect(ReportingService.normalizeIndicator('DOMAIN', 'https://www.sbi-fake.xyz/login')).toBe('sbi-fake.xyz');
    expect(ReportingService.normalizeIndicator('PHONE', '9876543210')).toBe('+919876543210');
    expect(ReportingService.normalizeIndicator('UPI_ID', ' scammer @ okaxis ')).toBe('scammer@okaxis');
  });

  it('enforces 4-state indicator lifecycle transitions', () => {
    // REPORTED -> UNDER_REVIEW (allowed)
    const t1 = ReportingService.transitionIndicatorState('REPORTED', 'UNDER_REVIEW');
    expect(t1.allowed).toBe(true);
    expect(t1.newStatus).toBe('UNDER_REVIEW');

    // UNDER_REVIEW -> VERIFIED (allowed)
    const t2 = ReportingService.transitionIndicatorState('UNDER_REVIEW', 'VERIFIED');
    expect(t2.allowed).toBe(true);
    expect(t2.newStatus).toBe('VERIFIED');

    // VERIFIED -> EXPIRED (allowed)
    const t3 = ReportingService.transitionIndicatorState('VERIFIED', 'EXPIRED');
    expect(t3.allowed).toBe(true);

    // Illegal skip: REPORTED -> EXPIRED (blocked)
    const illegal = ReportingService.transitionIndicatorState('REPORTED', 'EXPIRED');
    expect(illegal.allowed).toBe(false);
  });

  it('strictly rate-limits submissions (max 5 per minute)', () => {
    const clientId = `test_client_${Date.now()}`;

    // 5 submissions succeed
    for (let i = 0; i < 5; i++) {
      expect(() => {
        ReportingService.submitReport('DOMAIN', `phish-${i}.xyz`, 'KYC Scam', undefined, clientId);
      }).not.toThrow();
    }

    // 6th submission fails with RATE_LIMIT_EXCEEDED
    expect(() => {
      ReportingService.submitReport('DOMAIN', 'phish-overflow.xyz', 'KYC Scam', undefined, clientId);
    }).toThrow(/RATE_LIMIT_EXCEEDED/);
  });
});
