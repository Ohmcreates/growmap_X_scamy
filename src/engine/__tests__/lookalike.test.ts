import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../config.js';
import { extractAndAnalyzeUrls, levenshteinDistance } from '../lookalike.js';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 3 URL & Lookalike Threat Intelligence', () => {
  it('correctly calculates Levenshtein distance between brand tokens', () => {
    expect(levenshteinDistance('sbi', 'sbi')).toBe(0);
    expect(levenshteinDistance('sbi', 'sb1')).toBe(1);
    expect(levenshteinDistance('hdfc', 'hdfcb')).toBe(1);
    expect(levenshteinDistance('icici', 'icic1')).toBe(1);
  });

  it('flags IP address used as a host in links', () => {
    const text = 'Log in to your account at http://192.168.4.7/login to unlock card';
    const urls = extractAndAnalyzeUrls(text, DEFAULT_CONFIG.officialDomainAllowlist);

    expect(urls).toHaveLength(1);
    expect(urls[0].isSuspicious).toBe(true);
    expect(urls[0].reasons.some((r) => r.includes('IP address'))).toBe(true);
  });

  it('flags Punycode homoglyph domains', () => {
    const text = 'Please verify at https://xn--sbi-8ka.com/auth';
    const urls = extractAndAnalyzeUrls(text, DEFAULT_CONFIG.officialDomainAllowlist);

    expect(urls).toHaveLength(1);
    expect(urls[0].isSuspicious).toBe(true);
    expect(urls[0].reasons.some((r) => r.includes('Punycode'))).toBe(true);
  });

  it('flags brand name inside unofficial domain with odd TLD', () => {
    const text = 'Urgent KYC update: http://sbi-kyc-update.xyz/login';
    const urls = extractAndAnalyzeUrls(text, DEFAULT_CONFIG.officialDomainAllowlist);

    expect(urls).toHaveLength(1);
    expect(urls[0].isSuspicious).toBe(true);
    expect(urls[0].lookalikeTarget).toBe('SBI');
  });

  it('allows verified official banking domains without flagging', () => {
    const text = 'Check account balance at https://sbi.co.in or https://www.hdfcbank.com';
    const urls = extractAndAnalyzeUrls(text, DEFAULT_CONFIG.officialDomainAllowlist);

    expect(urls.every((u) => u.isAllowlisted)).toBe(true);
    expect(urls.every((u) => !u.isSuspicious)).toBe(true);
  });

  it('enforces floor rule (min 45 / High) when forced floor option is passed', () => {
    // Normal message with only a suspicious link scores 25 (Medium in 21-44 zone)
    const text = 'Check this link: http://sbi-kyc.xyz';
    const normalResult = analyzeMessage(text);
    expect(normalResult.score).toBe(25);
    expect(normalResult.riskLevel).toBe('MEDIUM');

    // With floor rule active (verified threat feed indicator match):
    const floorResult = analyzeMessage(text, DEFAULT_CONFIG, { forceFloorHigh: true });
    expect(floorResult.score).toBe(45);
    expect(floorResult.riskLevel).toBe('HIGH');
    expect(floorResult.floorApplied).toBe(true);
  });
});
