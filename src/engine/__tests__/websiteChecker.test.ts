import { describe, it, expect } from 'vitest';
import { checkWebsiteUrl } from '../websiteChecker.js';

describe('Scam Spotter — Dedicated Website Scam Checker (Reverse Engineered from IsThisSpam)', () => {
  it('correctly validates official allowlisted banking domains as safe and official', () => {
    const result = checkWebsiteUrl('https://sbi.co.in/portal/login');

    expect(result.isOfficialDomain).toBe(true);
    expect(result.classification).toBe('OFFICIAL_DOMAIN_VERIFIED');
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    expect(result.confidence).toBeGreaterThanOrEqual(0.95);
    expect(result.threats).toHaveLength(0);
  });

  it('detects brand lookalikes on suspicious TLDs with high confidence', () => {
    const result = checkWebsiteUrl('http://sbi-kyc-update.xyz/login');

    expect(result.isOfficialDomain).toBe(false);
    expect(result.classification).toBe('SCAM_DETECTED');
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
    expect(result.riskLevel).toBe('HIGH');
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);

    const threatIds = result.threats.map((t) => t.id);
    expect(threatIds).toContain('HIGH_RISK_TLD');
    expect(threatIds).toContain('BRAND_LOOKALIKE');
    expect(threatIds).toContain('HYPHEN_DECEPTION');
  });

  it('detects shortened URLs hiding destination targets', () => {
    const result = checkWebsiteUrl('http://bit.ly/indpst-fee');

    expect(result.isOfficialDomain).toBe(false);
    expect(result.metrics.isObfuscatedShortener).toBe(true);
    const threatIds = result.threats.map((t) => t.id);
    expect(threatIds).toContain('URL_SHORTENER_OBFUSCATION');
  });

  it('blocks SSRF private hosts and internal cloud metadata addresses', () => {
    const result = checkWebsiteUrl('http://169.254.169.254/latest/meta-data');

    expect(result.riskLevel).toBe('HIGH');
    const threatIds = result.threats.map((t) => t.id);
    expect(threatIds).toContain('SSRF_PRIVATE_HOST');
  });

  it('provides HTTPS padlock warning clarifying that free SSL does not mean trustworthy', () => {
    const result = checkWebsiteUrl('https://echallan-parivahan-gov.in.xyz');

    expect(result.metrics.sslWarning).toContain('Padlock (HTTPS) does NOT equal safety');
    expect(result.threats.length).toBeGreaterThan(0);
  });
});
