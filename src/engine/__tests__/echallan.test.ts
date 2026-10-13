import { describe, it, expect } from 'vitest';
import { analyzeMessage } from '../scorer.js';
import { checkWebsiteUrl } from '../websiteChecker.js';

describe('E-Challan Fake Message & URL Analysis', () => {
  const msg = 'Alert E-ChaIIan INR.1000 Generated: Vehicle no.OD02DJ8596 Challan no.OD11092445 paynow: https://mparivahan.redirectme.net/6/RTO.MoRTH';
  const url = 'https://mparivahan.redirectme.net/6/RTO.MoRTH';

  it('scans the fake e-Challan message and scores it as HIGH risk scam', () => {
    const result = analyzeMessage(msg);
    console.log('--- MESSAGE SCAN RESULT ---');
    console.log('Score:', result.score, 'Risk Level:', result.riskLevel);
    console.log('Breakdown:', result.breakdown.map((b) => `${b.ruleId} (+${b.awardedPoints})`));
    console.log('Profile:', result.scamProfile?.name);

    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.riskLevel).toBe('HIGH');
    expect(result.scamProfile).toBeDefined();
    expect(result.scamProfile?.id).toBe('TRAFFIC_CHALLAN');

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('AUTHORITY_IMPERSONATION');
    expect(firedIds).toContain('SUSPICIOUS_LINK');
  });

  it('evaluates the fake mparivahan URL and classifies it as SCAM_DETECTED with HIGH risk', () => {
    const siteResult = checkWebsiteUrl(url);
    console.log('--- WEBSITE CHECK RESULT ---');
    console.log('Risk Score:', siteResult.riskScore);
    console.log('Risk Level:', siteResult.riskLevel);
    console.log('Classification:', siteResult.classification);
    console.log('Threats:', siteResult.threats.map((t) => `${t.id}: ${t.title}`));
    console.log('Recommendations:', siteResult.recommendations);

    expect(siteResult.riskScore).toBeGreaterThanOrEqual(80);
    expect(siteResult.riskLevel).toBe('HIGH');
    expect(siteResult.classification).toBe('SCAM_DETECTED');
    expect(siteResult.threats.some((t) => t.id === 'DYNAMIC_DNS_OR_REDIRECTOR')).toBe(true);
    expect(siteResult.threats.some((t) => t.id === 'GOVERNMENT_PORTAL_IMPERSONATION')).toBe(true);
  });
});
