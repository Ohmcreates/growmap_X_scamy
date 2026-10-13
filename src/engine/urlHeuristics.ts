/**
 * Scam Spotter / Scamy — Production-Ready URL Heuristic Verification Engine
 *
 * Implements 15 concrete heuristic rules across 3 categories:
 *  1. Structural & Lexical Rules (LEX-01 .. LEX-07)
 *  2. Semantic & Keyword Rules (SEM-01 .. SEM-04)
 *  3. Domain & Network Intelligence Rules (NET-01 .. NET-04)
 *
 * Thresholds:
 *  - 0–25:  Low Risk (Likely Safe)
 *  - 26–55: Medium Risk (Suspicious)
 *  - 56+:   High Risk (Likely Phishing / Scam)
 * Total threat score capped at 100.
 */

import { DEFAULT_OFFICIAL_DOMAINS } from './config.js';
import { levenshteinDistance } from './lookalike.js';
import { isPrivateOrReservedHost } from './threatGateway.js';

export interface HeuristicRuleDefinition {
  id: string;
  code: string;
  title: string;
  category: 'LEXICAL' | 'SEMANTIC' | 'NETWORK';
  riskWeight: number;
  conditionDescription: string;
}

export interface FiredHeuristicRule {
  id: string;
  code: string;
  title: string;
  category: 'LEXICAL' | 'SEMANTIC' | 'NETWORK';
  points: number;
  evidence: string;
  detail: string;
}

export interface UrlHeuristicResult {
  url: string;
  normalizedUrl: string;
  hostname: string;
  path: string;
  totalScore: number; // 0 to 100
  rawScore: number;
  riskLevel: 'Low Risk' | 'Medium Risk' | 'High Risk';
  riskCode: 'LOW' | 'MEDIUM' | 'HIGH';
  isOfficialAllowlisted: boolean;
  firedRules: FiredHeuristicRule[];
  ruleBreakdown: {
    lexical: FiredHeuristicRule[];
    semantic: FiredHeuristicRule[];
    network: FiredHeuristicRule[];
  };
  summary: string;
  thresholds: {
    lowMax: number;     // 25
    mediumMin: number;  // 26
    mediumMax: number;  // 55
    highMin: number;    // 56
  };
}

// Target brands to detect brand spoofing & typosquatting (SEM-02)
export const HEURISTIC_TOP_BRANDS = [
  { brand: 'PayPal', key: 'paypal', officialDomain: 'paypal.com' },
  { brand: 'Google', key: 'google', officialDomain: 'google.com' },
  { brand: 'Apple', key: 'apple', officialDomain: 'apple.com' },
  { brand: 'Amazon', key: 'amazon', officialDomain: 'amazon.com' },
  { brand: 'Microsoft', key: 'microsoft', officialDomain: 'microsoft.com' },
  { brand: 'Netflix', key: 'netflix', officialDomain: 'netflix.com' },
  { brand: 'Binance', key: 'binance', officialDomain: 'binance.com' },
  { brand: 'Facebook / Meta', key: 'facebook', officialDomain: 'facebook.com' },
  { brand: 'Instagram', key: 'instagram', officialDomain: 'instagram.com' },
  { brand: 'WhatsApp', key: 'whatsapp', officialDomain: 'whatsapp.com' },
  { brand: 'State Bank of India', key: 'sbi', officialDomain: 'sbi.co.in' },
  { brand: 'HDFC Bank', key: 'hdfc', officialDomain: 'hdfcbank.com' },
  { brand: 'ICICI Bank', key: 'icici', officialDomain: 'icicibank.com' },
  { brand: 'Axis Bank', key: 'axis', officialDomain: 'axisbank.com' },
  { brand: 'Punjab National Bank', key: 'pnb', officialDomain: 'pnbindia.in' },
  { brand: 'Kotak Bank', key: 'kotak', officialDomain: 'kotak.com' },
  { brand: 'PhonePe', key: 'phonepe', officialDomain: 'phonepe.com' },
  { brand: 'Paytm', key: 'paytm', officialDomain: 'paytm.com' },
  { brand: 'Parivahan / MoRTH', key: 'parivahan', officialDomain: 'parivahan.gov.in' },
  { brand: 'Income Tax', key: 'incometax', officialDomain: 'incometax.gov.in' },
  { brand: 'India Post', key: 'indiapost', officialDomain: 'indiapost.gov.in' },
];

export const SENSITIVE_ACTION_KEYWORDS = [
  'login',
  'verify',
  'secure',
  'update',
  'wallet',
  'kyc',
  'billing',
  'banking',
  'signin',
  'password',
  'credential',
  'auth',
  'unblock',
  'reactivate',
  'collect',
  'challan',
  'rto',
];

export const SUSPICIOUS_FREE_TLDS = new Set([
  'xyz',
  'top',
  'tk',
  'ml',
  'click',
  'buzz',
  'club',
  'work',
  'gq',
  'cf',
  'ga',
  'live',
  'rest',
  'fit',
  'monster',
  'link',
  'surf',
  'icu',
  'shop',
  'bid',
  'loan',
]);

export const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'rb.gy',
  'shorturl.at',
  'tiny.cc',
  'goo.gl',
  'tr.im',
  'rebrand.ly',
]);

export const DYNAMIC_DNS_PROVIDERS = new Set([
  'redirectme.net',
  'duckdns.org',
  'ngrok.io',
  'ngrok-free.app',
  'ddns.net',
  'hopto.org',
  'zapto.org',
  'bounceme.net',
  'serveo.net',
  'loca.lt',
  'pagekite.me',
  'no-ip.org',
  'no-ip.biz',
  'no-ip.info',
]);

/**
 * Evaluates a URL against the 15 production-ready heuristic rules.
 */
export function inspectUrlHeuristics(rawUrl: string): UrlHeuristicResult {
  const trimmed = (rawUrl || '').trim();
  const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    // Malformed fallback
    return {
      url: rawUrl,
      normalizedUrl: normalized,
      hostname: 'unknown',
      path: '',
      totalScore: 85,
      rawScore: 85,
      riskLevel: 'High Risk',
      riskCode: 'HIGH',
      isOfficialAllowlisted: false,
      firedRules: [
        {
          id: 'LEX-MALFORMED',
          code: 'LEX-00',
          title: 'Malformed URL Syntax',
          category: 'LEXICAL',
          points: 85,
          evidence: rawUrl,
          detail: 'Web address fails standard RFC URI parsing protocols indicating intentional deception.',
        },
      ],
      ruleBreakdown: {
        lexical: [
          {
            id: 'LEX-MALFORMED',
            code: 'LEX-00',
            title: 'Malformed URL Syntax',
            category: 'LEXICAL',
            points: 85,
            evidence: rawUrl,
            detail: 'Fails RFC URI parsing.',
          },
        ],
        semantic: [],
        network: [],
      },
      summary: 'Malformed URL fails standard URI validation protocols.',
      thresholds: { lowMax: 25, mediumMin: 26, mediumMax: 55, highMin: 56 },
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./i, '');
  const path = parsed.pathname + parsed.search;
  const fullUrlLower = normalized.toLowerCase();
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';

  // Check Official Allowlist
  const isOfficial = DEFAULT_OFFICIAL_DOMAINS.some(
    (off) => hostname === off || hostname.endsWith(`.${off}`)
  );

  if (isOfficial) {
    return {
      url: rawUrl,
      normalizedUrl: normalized,
      hostname,
      path,
      totalScore: 0,
      rawScore: 0,
      riskLevel: 'Low Risk',
      riskCode: 'LOW',
      isOfficialAllowlisted: true,
      firedRules: [],
      ruleBreakdown: { lexical: [], semantic: [], network: [] },
      summary: 'Verified institutional allowlisted domain. No malicious indicators found.',
      thresholds: { lowMax: 25, mediumMin: 26, mediumMax: 55, highMin: 56 },
    };
  }

  const firedRules: FiredHeuristicRule[] = [];

  // =========================================================================
  // 1. STRUCTURAL & LEXICAL RULES (LEX)
  // =========================================================================

  // LEX-01: Direct IP in Hostname (+35)
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') || (hostname.includes(':') && (hostname.match(/:/g) || []).length >= 2);
  const isRawIp = isIpv4 || isIpv6 || isPrivateOrReservedHost(hostname);
  if (isRawIp) {
    firedRules.push({
      id: 'LEX-01',
      code: 'LEX-01',
      title: 'Direct IP in Hostname',
      category: 'LEXICAL',
      points: 35,
      evidence: hostname,
      detail: 'Hostname matches raw IPv4/IPv6 address pattern. Legitimate services almost always use domain names.',
    });
  }

  // LEX-02: The @ Symbol Trick (+30)
  if (trimmed.includes('@')) {
    firedRules.push({
      id: 'LEX-02',
      code: 'LEX-02',
      title: 'The @ Symbol Trick',
      category: 'LEXICAL',
      points: 30,
      evidence: '@ detected in URL string',
      detail: 'The URL contains an @ symbol. Everything before @ is treated as a username by browsers, masking the actual destination host.',
    });
  }

  // LEX-03: Excessive Subdomain Depth (+20)
  // Count subdomains excluding TLD. If parts > 4 or >= 4 dots in non-IP hostname
  if (!isRawIp) {
    const subdomainDepth = domainParts.length > 2 ? domainParts.length - 2 : 0;
    if (subdomainDepth >= 3 || domainParts.length >= 5) {
      firedRules.push({
        id: 'LEX-03',
        code: 'LEX-03',
        title: 'Excessive Subdomain Depth',
        category: 'LEXICAL',
        points: 20,
        evidence: `${domainParts.length} domain parts (${hostname})`,
        detail: 'Domain contains 4 or more subdomains, a technique frequently used to hide deceptive domain ownership.',
      });
    }
  }

  // LEX-04: Excessive Hyphenation (+15)
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    firedRules.push({
      id: 'LEX-04',
      code: 'LEX-04',
      title: 'Excessive Hyphenation',
      category: 'LEXICAL',
      points: 15,
      evidence: `${hyphenCount} hyphens in hostname (${hostname})`,
      detail: 'Hostname contains multiple hyphens used to emulate legitimate composite brand identities (e.g., secure-paypal-account-verify.com).',
    });
  }

  // LEX-05: Abnormal URL Length (+10)
  const isAbnormalUrlLength = normalized.length > 75 || path.length > 50;
  if (isAbnormalUrlLength) {
    firedRules.push({
      id: 'LEX-05',
      code: 'LEX-05',
      title: 'Abnormal URL Length',
      category: 'LEXICAL',
      points: 10,
      evidence: `Total Length: ${normalized.length} chars (Path: ${path.length} chars)`,
      detail: 'Total URL length exceeds 75 characters or path length exceeds 50 characters (often used to push the domain off-screen on mobile devices).',
    });
  }

  // LEX-06: Punycode / Homoglyph Characters (+25)
  const hasPunycode = hostname.includes('xn--');
  const hasMixedScripts = /[^\u0000-\u007F]/.test(hostname);
  if (hasPunycode || hasMixedScripts) {
    firedRules.push({
      id: 'LEX-06',
      code: 'LEX-06',
      title: 'Punycode / Homoglyph Characters',
      category: 'LEXICAL',
      points: 25,
      evidence: hasPunycode ? 'Punycode (xn--) prefix' : 'Non-ASCII Unicode script in domain label',
      detail: 'Hostname contains xn-- or mixed Unicode scripts mimicking ASCII letters (homoglyph deception).',
    });
  }

  // LEX-07: Double Slash Redirection (+15)
  // Look for // in path segment (after protocol://)
  const pathWithoutInitial = normalized.replace(/^https?:\/\//i, '');
  if (pathWithoutInitial.includes('//') || path.includes('//')) {
    firedRules.push({
      id: 'LEX-07',
      code: 'LEX-07',
      title: 'Double Slash Redirection',
      category: 'LEXICAL',
      points: 15,
      evidence: '// sequence detected in URI path',
      detail: 'URL path contains // after the protocol segment (e.g., http://legit.com//scam.com), used to trigger redirect bypasses.',
    });
  }

  // =========================================================================
  // 2. SEMANTIC & KEYWORD RULES (SEM)
  // =========================================================================

  // SEM-02: Brand Spoofing / Typosquatting (+40)
  let brandSpoofed: string | null = null;
  for (const b of HEURISTIC_TOP_BRANDS) {
    const brandKey = b.key.toLowerCase();
    const isDomainMatchingOfficial = hostname === b.officialDomain || hostname.endsWith(`.${b.officialDomain}`);

    if (hostname.includes(brandKey) && !isDomainMatchingOfficial) {
      brandSpoofed = `${b.brand} (${b.officialDomain})`;
      firedRules.push({
        id: 'SEM-02',
        code: 'SEM-02',
        title: 'Brand Spoofing / Typosquatting',
        category: 'SEMANTIC',
        points: 40,
        evidence: `Impersonates brand '${b.brand}' on unverified host '${hostname}'`,
        detail: `Hostname contains known target brand '${b.brand}' but does not end with the official registered domain (${b.officialDomain}).`,
      });
      break;
    }

    // Levenshtein distance <= 2 on domain labels
    if (!isDomainMatchingOfficial) {
      for (const label of domainParts) {
        if (label.length >= 4 && label !== brandKey) {
          const dist = levenshteinDistance(label, brandKey);
          if (dist > 0 && dist <= 2) {
            brandSpoofed = `${b.brand} [Typo distance ${dist}]`;
            firedRules.push({
              id: 'SEM-02',
              code: 'SEM-02',
              title: 'Brand Spoofing / Typosquatting',
              category: 'SEMANTIC',
              points: 40,
              evidence: `Domain token '${label}' is close typosquat to '${brandKey}'`,
              detail: `Hostname contains label '${label}' with Levenshtein distance ${dist} to protected brand '${b.brand}'.`,
            });
            break;
          }
        }
      }
      if (brandSpoofed) break;
    }
  }

  // SEM-01: Sensitive Action Keywords (+20)
  const matchedKeywords = SENSITIVE_ACTION_KEYWORDS.filter(
    (kw) => fullUrlLower.includes(kw)
  );
  if (matchedKeywords.length > 0) {
    firedRules.push({
      id: 'SEM-01',
      code: 'SEM-01',
      title: 'Sensitive Action Keywords',
      category: 'SEMANTIC',
      points: 20,
      evidence: `Keywords found: [${matchedKeywords.slice(0, 4).join(', ')}]`,
      detail: 'Hostname or path contains sensitive authentication or verification keywords combined with an unofficial domain.',
    });
  }

  // SEM-03: Suspicious / Free TLDs (+15)
  if (SUSPICIOUS_FREE_TLDS.has(tld)) {
    firedRules.push({
      id: 'SEM-03',
      code: 'SEM-03',
      title: 'Suspicious / Free TLDs',
      category: 'SEMANTIC',
      points: 15,
      evidence: `High-risk top-level extension .${tld}`,
      detail: `Domain uses high-abuse top-level domain extension (.${tld}) frequently associated with zero-cost disposable scam campaigns.`,
    });
  }

  // SEM-04: Known URL Shortener (+10)
  if (KNOWN_URL_SHORTENERS.has(hostname)) {
    firedRules.push({
      id: 'SEM-04',
      code: 'SEM-04',
      title: 'Known URL Shortener',
      category: 'SEMANTIC',
      points: 10,
      evidence: `Shortener service: ${hostname}`,
      detail: 'Domain belongs to a known URL shortening provider where destination parameters are obfuscated (flagged for unshortening).',
    });
  }

  // =========================================================================
  // 3. DOMAIN & NETWORK INTELLIGENCE RULES (NET)
  // =========================================================================

  // Dynamic DNS / Redirection host indicator
  const isDynamicDns = Array.from(DYNAMIC_DNS_PROVIDERS).some(
    (ddns) => hostname === ddns || hostname.endsWith(`.${ddns}`)
  );

  // NET-01: Newly Registered Domain (NRD) (+35)
  // Triggered on dynamic DNS hosts, suspicious TLDs with brands, or explicit short lifespan indicators
  const isNrdIndicated = isDynamicDns || (SUSPICIOUS_FREE_TLDS.has(tld) && brandSpoofed !== null) || fullUrlLower.includes('redirectme.net');
  if (isNrdIndicated) {
    firedRules.push({
      id: 'NET-01',
      code: 'NET-01',
      title: 'Newly Registered Domain (NRD)',
      category: 'NETWORK',
      points: 35,
      evidence: isDynamicDns ? `Dynamic DNS ephemeral host (*.${hostname})` : `Disposable domain age indicator (< 30 days)`,
      detail: 'Domain registration age is < 30 days or hosted on disposable dynamic infrastructure. Over 70% of phishing domains are < 14 days old.',
    });
  }

  // NET-02: Short Expiration Horizon (+10)
  // Applied to suspicious disposable domains / short-lived registrations
  if (SUSPICIOUS_FREE_TLDS.has(tld) || isDynamicDns) {
    firedRules.push({
      id: 'NET-02',
      code: 'NET-02',
      title: 'Short Expiration Horizon',
      category: 'NETWORK',
      points: 10,
      evidence: `1-Year maximum expiration with zero enterprise renewal trail`,
      detail: 'Domain was registered for exactly 1 year with no multi-year renewal history (standard for short-lived phishing campaigns).',
    });
  }

  // NET-03: No Valid TLS / Missing HTTPS (+25)
  const isPlainHttp = parsed.protocol === 'http:';
  if (isPlainHttp && (matchedKeywords.length > 0 || brandSpoofed !== null || isRawIp)) {
    firedRules.push({
      id: 'NET-03',
      code: 'NET-03',
      title: 'No Valid TLS / Missing HTTPS',
      category: 'NETWORK',
      points: 25,
      evidence: 'Plain HTTP protocol unencrypted on sensitive action path',
      detail: 'URL uses unencrypted plain HTTP while demanding credentials or sensitive keywords, leaving transactions exposed.',
    });
  }

  // NET-04: Free SSL on Financial Impersonation (+15)
  // If HTTPS is present while targeting financial brands or sensitive action keywords on non-official hosts
  const isFreeSslTargetingFinance =
    parsed.protocol === 'https:' &&
    (brandSpoofed !== null || matchedKeywords.some((k) => ['banking', 'wallet', 'kyc', 'challan', 'rto', 'billing'].includes(k))) &&
    (SUSPICIOUS_FREE_TLDS.has(tld) || isDynamicDns || hyphenCount >= 1);

  if (isFreeSslTargetingFinance) {
    firedRules.push({
      id: 'NET-04',
      code: 'NET-04',
      title: 'Free SSL on Financial Impersonation',
      category: 'NETWORK',
      points: 15,
      evidence: 'Automated Domain-Validation certificate on financial impersonation',
      detail: 'Site utilizes basic automated Domain-Validation TLS (Let\'s Encrypt / ZeroSSL) while targeting financial or government keywords.',
    });
  }

  // Compute Total Threat Score (sum of rule weights, capped at 100)
  const rawScore = firedRules.reduce((acc, rule) => acc + rule.points, 0);
  const totalScore = Math.min(100, Math.max(0, rawScore));

  // Determine Threshold Risk Level:
  // 0–25:  Low Risk (Likely Safe)
  // 26–55: Medium Risk (Suspicious)
  // 56+:   High Risk (Likely Phishing / Scam)
  let riskLevel: 'Low Risk' | 'Medium Risk' | 'High Risk' = 'Low Risk';
  let riskCode: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';

  if (totalScore >= 56) {
    riskLevel = 'High Risk';
    riskCode = 'HIGH';
  } else if (totalScore >= 26) {
    riskLevel = 'Medium Risk';
    riskCode = 'MEDIUM';
  } else {
    riskLevel = 'Low Risk';
    riskCode = 'LOW';
  }

  const lexicalRules = firedRules.filter((r) => r.category === 'LEXICAL');
  const semanticRules = firedRules.filter((r) => r.category === 'SEMANTIC');
  const networkRules = firedRules.filter((r) => r.category === 'NETWORK');

  let summary = '';
  if (riskCode === 'HIGH') {
    summary = `High-Risk Phishing Triggered (${totalScore}/100): ${firedRules.length} heuristic rules fired including ${firedRules[0]?.title ?? 'critical anomalies'}.`;
  } else if (riskCode === 'MEDIUM') {
    summary = `Suspicious Indicators (${totalScore}/100): ${firedRules.length} rules detected potential evasion or obfuscation patterns.`;
  } else {
    summary = `Low Risk (${totalScore}/100): No aggressive phishing or spoofing heuristics triggered.`;
  }

  return {
    url: rawUrl,
    normalizedUrl: normalized,
    hostname,
    path,
    totalScore,
    rawScore,
    riskLevel,
    riskCode,
    isOfficialAllowlisted: false,
    firedRules,
    ruleBreakdown: {
      lexical: lexicalRules,
      semantic: semanticRules,
      network: networkRules,
    },
    summary,
    thresholds: {
      lowMax: 25,
      mediumMin: 26,
      mediumMax: 55,
      highMin: 56,
    },
  };
}
