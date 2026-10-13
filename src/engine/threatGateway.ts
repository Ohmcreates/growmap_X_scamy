export interface ThreatLookupResult {
  domain: string;
  isMalicious: boolean;
  threatType?: string;
  source: string;
  cached: boolean;
  responseTimeMs: number;
}

const PRIVATE_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^169\.254\./, // AWS / GCP metadata endpoint
  /^0\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/,
];

export function isPrivateOrReservedHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  if (normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1') {
    return true;
  }

  // Check IPv4 patterns
  return PRIVATE_IP_PATTERNS.some((pat) => pat.test(normalized));
}

interface CacheEntry {
  result: ThreatLookupResult;
  expiresAt: number;
}

export class ThreatIntelligenceGateway {
  private cache = new Map<string, CacheEntry>();
  private defaultTtlMs = 4 * 60 * 60 * 1000; // 4 hours

  // Known threat feed simulated database
  private knownBadFeed = new Set([
    'sbi-kyc-update.xyz',
    'hdfc-security-update.top',
    'phonepe-reward-claim.live',
    'paytm-kyc-login.click',
    'customs-held-parcel.xyz',
  ]);

  clearCache(): void {
    this.cache.clear();
  }

  async lookupDomain(
    rawDomain: string,
    timeoutMs = 1500
  ): Promise<ThreatLookupResult> {
    const start = performance.now();
    const domain = rawDomain.trim().toLowerCase();

    // 1. SSRF Defense: Check if domain resolves to internal/private IP
    if (isPrivateOrReservedHost(domain)) {
      const duration = performance.now() - start;
      return {
        domain,
        isMalicious: true,
        threatType: 'SSRF_BLOCKED_INTERNAL_DESTINATION',
        source: 'SSRF Shield',
        cached: false,
        responseTimeMs: duration,
      };
    }

    // 2. Check in-memory cache
    const cachedEntry = this.cache.get(domain);
    if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
      const duration = performance.now() - start;
      return {
        ...cachedEntry.result,
        cached: true,
        responseTimeMs: duration,
      };
    }

    // 3. Simulated external threat provider lookup with timeout protection
    const isBad = this.knownBadFeed.has(domain);

    const lookupPromise = new Promise<ThreatLookupResult>((resolve) => {
      // Simulate network roundtrip (20ms)
      setTimeout(() => {
        const duration = performance.now() - start;
        const result: ThreatLookupResult = {
          domain,
          isMalicious: isBad,
          threatType: isBad ? 'PHISHING_CREDENTIAL_HARVESTING' : undefined,
          source: isBad ? 'National Phishing Feed' : 'Threat Intelligence Gateway',
          cached: false,
          responseTimeMs: duration,
        };
        resolve(result);
      }, 20);
    });

    const timeoutPromise = new Promise<ThreatLookupResult>((resolve) => {
      setTimeout(() => {
        const duration = performance.now() - start;
        resolve({
          domain,
          isMalicious: false,
          threatType: 'LOOKUP_TIMEOUT_FALLBACK',
          source: 'Graceful Fallback',
          cached: false,
          responseTimeMs: duration,
        });
      }, timeoutMs);
    });

    const finalResult = await Promise.race([lookupPromise, timeoutPromise]);

    // Store in cache
    this.cache.set(domain, {
      result: finalResult,
      expiresAt: Date.now() + this.defaultTtlMs,
    });

    return finalResult;
  }
}
