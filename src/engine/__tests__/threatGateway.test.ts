import { beforeEach, describe, expect, it } from 'vitest';
import { isPrivateOrReservedHost, ThreatIntelligenceGateway } from '../threatGateway.js';

describe('Scam Spotter — Phase 3 Threat Gateway & SSRF Protection', () => {
  let gateway: ThreatIntelligenceGateway;

  beforeEach(() => {
    gateway = new ThreatIntelligenceGateway();
    gateway.clearCache();
  });

  it('detects and blocks private/internal IPs to prevent SSRF', () => {
    expect(isPrivateOrReservedHost('localhost')).toBe(true);
    expect(isPrivateOrReservedHost('127.0.0.1')).toBe(true);
    expect(isPrivateOrReservedHost('169.254.169.254')).toBe(true); // AWS/cloud metadata
    expect(isPrivateOrReservedHost('192.168.1.1')).toBe(true);
    expect(isPrivateOrReservedHost('10.0.0.5')).toBe(true);
    expect(isPrivateOrReservedHost('sbi.co.in')).toBe(false);
  });

  it('safely blocks lookup of internal host with SSRF shield result', async () => {
    const result = await gateway.lookupDomain('169.254.169.254');
    expect(result.isMalicious).toBe(true);
    expect(result.threatType).toBe('SSRF_BLOCKED_INTERNAL_DESTINATION');
  });

  it('identifies confirmed malicious domains from feed', async () => {
    const result = await gateway.lookupDomain('sbi-kyc-update.xyz');
    expect(result.isMalicious).toBe(true);
    expect(result.threatType).toBe('PHISHING_CREDENTIAL_HARVESTING');
  });

  it('serves cached queries in under 50ms satisfying Phase 3 SLA', async () => {
    // Prime cache
    await gateway.lookupDomain('example-bank-check.com');

    // Second call must hit cache
    const cachedResult = await gateway.lookupDomain('example-bank-check.com');
    expect(cachedResult.cached).toBe(true);
    expect(cachedResult.responseTimeMs).toBeLessThan(50); // Under 50ms SLA
  });
});
