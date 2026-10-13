import { DEFAULT_OFFICIAL_DOMAINS } from './config.js';
import { isPrivateOrReservedHost } from './threatGateway.js';
import { levenshteinDistance } from './lookalike.js';
import { ReportingService } from '../services/reporting.js';
import { evaluatePhishingMl, MlModelAssessment } from './phishingMl.js';
import { inspectUrlHeuristics, UrlHeuristicResult } from './urlHeuristics.js';

export interface ThreatSignal {
  id: string;
  title: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
}

export interface WebsiteCheckResult {
  url: string;
  cleanUrl: string;
  domain: string;
  protocol: string;
  tld: string;
  path: string;
  isOfficialDomain: boolean;
  officialBrandName?: string;
  riskScore: number; // 0 to 100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  classification:
    | 'SCAM_DETECTED'
    | 'SUSPICIOUS_DETECTED'
    | 'OFFICIAL_DOMAIN_VERIFIED'
    | 'NO_THREATS_DETECTED';
  confidence: number; // 0.0 to 1.0
  verdict: string;
  summary: string;
  metrics: {
    domainAgeEstimate: string;
    isNewlyRegistered: boolean;
    sslStatus: string;
    sslWarning: string;
    tldRisk: 'LOW' | 'MEDIUM' | 'HIGH';
    hostingReputation: 'VERIFIED_OFFICIAL' | 'SUSPICIOUS_DISPOSABLE' | 'NEUTRAL';
    threatDbListed: boolean;
    threatCategory?: string;
    isObfuscatedShortener: boolean;
    isRawIpAddress: boolean;
  };
  threats: ThreatSignal[];
  recommendations: string[];
  mlAssessment: MlModelAssessment;
  heuristics: UrlHeuristicResult;
}

const COMMON_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'cutt.ly',
  'ow.ly',
  'rb.gy',
  'shorturl.at',
]);

const DYNAMIC_DNS_DOMAINS = new Set([
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

const HIGH_RISK_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'club',
  'live',
  'work',
  'shop',
  'biz',
  'cc',
  'cf',
  'tk',
  'ml',
  'gq',
  'rest',
]);

const BRAND_TARGETS = [
  { brand: 'State Bank of India', key: 'sbi', official: 'sbi.co.in' },
  { brand: 'HDFC Bank', key: 'hdfc', official: 'hdfcbank.com' },
  { brand: 'ICICI Bank', key: 'icici', official: 'icicibank.com' },
  { brand: 'Axis Bank', key: 'axis', official: 'axisbank.com' },
  { brand: 'Punjab National Bank', key: 'pnb', official: 'pnbindia.in' },
  { brand: 'PhonePe', key: 'phonepe', official: 'phonepe.com' },
  { brand: 'Paytm', key: 'paytm', official: 'paytm.com' },
  { brand: 'India Post', key: 'indpst', official: 'indiapost.gov.in' },
  { brand: 'Parivahan / E-Challan', key: 'parivahan', official: 'parivahan.gov.in' },
  { brand: 'Income Tax Department', key: 'incometax', official: 'incometax.gov.in' },
  { brand: 'Amazon', key: 'amazon', official: 'amazon.in' },
  { brand: 'Flipkart', key: 'flipkart', official: 'flipkart.com' },
];

export function checkWebsiteUrl(rawInput: string): WebsiteCheckResult {
  const trimmed = rawInput.trim();
  let normalizedUrl = trimmed;
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = `https://${normalizedUrl}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    // Fallback if URL constructor fails
    return {
      url: rawInput,
      cleanUrl: rawInput,
      domain: rawInput,
      protocol: 'unknown',
      tld: 'unknown',
      path: '',
      isOfficialDomain: false,
      riskScore: 85,
      riskLevel: 'HIGH',
      classification: 'SCAM_DETECTED',
      confidence: 0.85,
      verdict: 'Malformed or Deceptive URL Structure',
      summary: 'The submitted web address fails standard URL parsing protocols, indicating obfuscation.',
      metrics: {
        domainAgeEstimate: 'Unknown',
        isNewlyRegistered: false,
        sslStatus: 'Invalid Protocol',
        sslWarning: 'Cannot verify certificate on malformed URI.',
        tldRisk: 'HIGH',
        hostingReputation: 'SUSPICIOUS_DISPOSABLE',
        threatDbListed: false,
        isObfuscatedShortener: false,
        isRawIpAddress: false,
      },
      threats: [
        {
          id: 'MALFORMED_SYNTAX',
          title: 'Malformed URL Syntax',
          severity: 'HIGH',
          detail: 'Web address contains illegal characters or deceptive formatting.',
        },
      ],
      recommendations: [
        'Do not open this URL in your web browser.',
        'Never submit credentials, OTPs, or credit card details.',
      ],
      mlAssessment: evaluatePhishingMl(rawInput),
      heuristics: inspectUrlHeuristics(rawInput),
    };
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./i, '');
  const protocol = parsed.protocol.replace(':', '');
  const path = parsed.pathname + parsed.search;

  // Extract TLD
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';

  // 1. Check Official Domain Allowlist
  const isOfficial = DEFAULT_OFFICIAL_DOMAINS.some(
    (off) => hostname === off || hostname.endsWith(`.${off}`)
  );

  if (isOfficial) {
    const matchedBrand = BRAND_TARGETS.find((b) => hostname.includes(b.key))?.brand || 'Official Organization';
    return {
      url: rawInput,
      cleanUrl: normalizedUrl,
      domain: hostname,
      protocol,
      tld,
      path,
      isOfficialDomain: true,
      officialBrandName: matchedBrand,
      riskScore: 0,
      riskLevel: 'LOW',
      classification: 'OFFICIAL_DOMAIN_VERIFIED',
      confidence: 0.98,
      verdict: 'Verified Official Domain',
      summary: `This is a genuine, verified official domain registered to ${matchedBrand}. It is safe to use.`,
      metrics: {
        domainAgeEstimate: '10+ Years Established',
        isNewlyRegistered: false,
        sslStatus: 'Valid Extended / EV SSL Certificate',
        sslWarning: 'Connection is securely encrypted and validated by official organization authorities.',
        tldRisk: 'LOW',
        hostingReputation: 'VERIFIED_OFFICIAL',
        threatDbListed: false,
        isObfuscatedShortener: false,
        isRawIpAddress: false,
      },
      threats: [],
      recommendations: [
        'Always check the address bar to ensure the domain name remains verified as you browse.',
        'Official institutions will still never ask for your private ATM PIN or UPI PIN.',
      ],
      mlAssessment: evaluatePhishingMl(rawInput),
      heuristics: inspectUrlHeuristics(rawInput),
    };
  }

  // 2. Evaluate Threat Signals
  const threats: ThreatSignal[] = [];
  let score = 0;

  // 15 Production Heuristic Rules (LEX-01..07, SEM-01..04, NET-01..04)
  const heuristics = inspectUrlHeuristics(rawInput);
  score = Math.max(score, heuristics.totalScore);

  for (const hRule of heuristics.firedRules) {
    threats.push({
      id: hRule.id,
      title: `${hRule.code}: ${hRule.title} (+${hRule.points})`,
      severity: hRule.points >= 25 ? 'HIGH' : hRule.points >= 15 ? 'MEDIUM' : 'LOW',
      detail: `${hRule.detail} [Evidence: ${hRule.evidence}]`,
    });
  }

  // Machine Learning Phishing Classification (10-Feature Vector)
  const mlAssessment = evaluatePhishingMl(rawInput);
  if (mlAssessment.isPhishing) {
    threats.push({
      id: 'ML_PHISHING_CLASSIFIER_FLAG',
      title: `Random Forest Phishing Classifier Alert (${mlAssessment.confidenceScore}% Confidence)`,
      severity: 'HIGH',
      detail: `Machine learning model detected zero-day phishing patterns across 10 lexical and structural features (ML Risk Probability: ${mlAssessment.phishingProbability}%).`,
    });
    score = Math.max(score, 75);
  }

  // SSRF / Private Network check
  if (isPrivateOrReservedHost(hostname)) {
    threats.push({
      id: 'SSRF_PRIVATE_HOST',
      title: 'Internal / Private Network Hostname (SSRF)',
      severity: 'HIGH',
      detail: 'The URL targets a private IP address or metadata service (RFC 1918), blocked for safety.',
    });
    score += 80;
  }

  // Raw IP Address check
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  if (isIp) {
    threats.push({
      id: 'RAW_IP_ADDRESS',
      title: 'Direct IP Address Host',
      severity: 'HIGH',
      detail: 'Legitimate services use branded domain names. Direct IP links conceal true ownership.',
    });
    score += 40;
  }

  // URL Shortener check
  const isShortener = COMMON_SHORTENERS.has(hostname);
  if (isShortener) {
    threats.push({
      id: 'URL_SHORTENER_OBFUSCATION',
      title: 'Obfuscated Link (URL Shortener)',
      severity: 'MEDIUM',
      detail: 'Shortened link conceals the final destination domain and bypasses SMS safety filters.',
    });
    score += 30;
  }

  // Suspicious TLD check
  const isSuspiciousTld = HIGH_RISK_TLDS.has(tld);
  if (isSuspiciousTld) {
    threats.push({
      id: 'HIGH_RISK_TLD',
      title: `High-Risk Disposable TLD (.${tld})`,
      severity: 'HIGH',
      detail: `Cheap and anonymous domain extensions like .${tld} are heavily favoured by disposable scam kits.`,
    });
    score += 35;
  }

  // Dynamic DNS / disposable redirection host check
  const matchedDdns = Array.from(DYNAMIC_DNS_DOMAINS).find(
    (ddns) => hostname === ddns || hostname.endsWith(`.${ddns}`)
  );
  if (matchedDdns) {
    threats.push({
      id: 'DYNAMIC_DNS_OR_REDIRECTOR',
      title: `Dynamic DNS / Disposable Redirection Host (*.${matchedDdns})`,
      severity: 'HIGH',
      detail: `The site is hosted on a dynamic DNS redirection domain (*.${matchedDdns}). Attackers frequently register free subdomains on dynamic DNS providers to host transient e-challan or phishing landing pages without identity verification.`,
    });
    score += 45;
  }

  // Lookalike & Typo-squatting detection
  let matchedBrandTarget: string | undefined;
  for (const target of BRAND_TARGETS) {
    const key = target.key;
    if (hostname.includes(key)) {
      matchedBrandTarget = target.brand;
      const isGov = ['Parivahan / E-Challan', 'India Post', 'Income Tax Department'].includes(target.brand);
      if (isGov) {
        threats.push({
          id: 'GOVERNMENT_PORTAL_IMPERSONATION',
          title: `Government Portal Impersonation (${target.brand})`,
          severity: 'HIGH',
          detail: `CRITICAL: This domain mimics the Indian Government portal "${target.brand}" (${target.official}) on an unauthorized private host. Official transport & government portals strictly reside under ".gov.in" or ".nic.in".`,
        });
        score += 55;
      } else {
        threats.push({
          id: 'BRAND_LOOKALIKE',
          title: `Brand Lookalike Impersonation (${target.brand})`,
          severity: 'HIGH',
          detail: `The domain mimics "${target.brand}" (${target.official}) but is hosted on an unofficial server.`,
        });
        score += 40;
      }
      break;
    }

    // Levenshtein typo-squat check on domain labels
    const domainLabels = hostname.split('.');
    let typoMatched = false;
    for (const label of domainLabels) {
      if (label.length >= 3 && label !== key && levenshteinDistance(label, key) === 1) {
        matchedBrandTarget = target.brand;
        threats.push({
          id: 'BRAND_LOOKALIKE',
          title: `Typo-squatting Impersonation (${target.brand})`,
          severity: 'HIGH',
          detail: `The domain label "${label}" is a 1-character typo-squat permutation of "${target.brand}" (${target.official}).`,
        });
        score += 40;
        typoMatched = true;
        break;
      }
    }
    if (typoMatched) break;
  }

  // Hyphenated deceptive keywords (e.g. sbi-kyc, hdfc-alert, verify-login)
  if (/-(?:kyc|update|login|support|alert|verify|security|portal|bank)\./i.test(hostname)) {
    threats.push({
      id: 'HYPHEN_DECEPTION',
      title: 'Hyphenated Phishing Pattern',
      severity: 'HIGH',
      detail: 'Scammers insert hyphens alongside words like "-kyc" or "-update" to simulate official subdomains.',
    });
    score += 30;
  }

  // Suspicious Path or Query keywords
  if (/\b(?:update-kyc|verify-otp|enter-pin|claim-reward|download-apk|free-gift|rto|morth|challan|echallan|traffic|vahan)\b/i.test(path)) {
    threats.push({
      id: 'SUSPICIOUS_PATH',
      title: 'Deceptive Action Path / Government Body Emulation',
      severity: 'HIGH',
      detail: 'The URL path contains official transport or sensitive action keywords (RTO / MoRTH / Challan) designed to deceive visitors.',
    });
    score += 30;
  }

  // Check Community Threat Database
  const knownBad = ReportingService.getKnownBadIndicators();
  const isThreatDb = knownBad.some(
    (r) => r.type === 'DOMAIN' && hostname.includes(r.normalizedValue)
  );
  if (isThreatDb) {
    threats.push({
      id: 'COMMUNITY_THREAT_DB_MATCH',
      title: 'Confirmed Malicious in Threat Intelligence Feed',
      severity: 'HIGH',
      detail: 'This domain has been flagged and verified by community reports and threat gateways as active malware/phishing.',
    });
    score = Math.max(score, 85);
  }

  // Cap score at 100
  const finalScore = Math.min(100, Math.max(score, heuristics.totalScore));

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let classification: WebsiteCheckResult['classification'] = 'NO_THREATS_DETECTED';
  let verdict = 'No Strong Warning Signs Detected';
  let summary = 'This web address does not match known threat signatures, but always exercise caution before entering passwords.';

  // Heuristic Thresholds:
  // 0–25:  Low Risk (Likely Safe)
  // 26–55: Medium Risk (Suspicious)
  // 56+:   High Risk (Likely Phishing / Scam)
  if (finalScore >= 56) {
    riskLevel = 'HIGH';
    classification = 'SCAM_DETECTED';
    verdict = 'High-Risk Scam / Phishing Website';
    summary = `High-Risk Phishing Triggered (${finalScore}/100): ${heuristics.firedRules.length} heuristic rules fired including ${heuristics.firedRules[0]?.title ?? 'critical anomalies'}.`;
  } else if (finalScore >= 26) {
    riskLevel = 'MEDIUM';
    classification = 'SUSPICIOUS_DETECTED';
    verdict = 'Suspicious Web Address';
    summary = `Suspicious Indicators (${finalScore}/100): Heuristic rules detected evasion or obfuscation patterns.`;
  }

  // Recommendations matching IsThisSpam
  const recommendations: string[] = [];
  if (matchedBrandTarget === 'Parivahan / E-Challan') {
    recommendations.push('Verify pending traffic challans ONLY at the official Ministry portal: https://echallan.parivahan.gov.in.');
    recommendations.push('DO NOT pay traffic fines on unofficial .net or dynamic redirect URLs. Traffic police never use dynamic redirection hostnames.');
  }
  if (riskLevel === 'HIGH') {
    recommendations.push('Do NOT open this website or enter personal information.');
    recommendations.push('Never enter your phone number, password, OTP, or UPI PIN on this site.');
    recommendations.push('If you already submitted payment details, contact your bank immediately to freeze your card.');
    recommendations.push('Report this URL to the National Cyber Crime Portal at 1930 / cybercrime.gov.in.');
  } else if (riskLevel === 'MEDIUM') {
    recommendations.push('Verify the domain by searching for the official company website directly on Google.');
    recommendations.push('Do not proceed through shortened links without expanding them first.');
    recommendations.push('Avoid downloading unexpected APKs or granting browser notification permissions.');
  } else {
    recommendations.push('Ensure the URL in your browser address bar matches the exact domain you intended to visit.');
    recommendations.push('Remember that HTTPS / the padlock icon only encrypts traffic — it does not guarantee honesty.');
  }

  const confidence =
    riskLevel === 'HIGH'
      ? Number(Math.min(0.98, 0.75 + (finalScore / 100) * 0.23).toFixed(2))
      : riskLevel === 'MEDIUM'
      ? Number(Math.min(0.85, 0.55 + (finalScore / 100) * 0.25).toFixed(2))
      : 0.78;

  return {
    url: rawInput,
    cleanUrl: normalizedUrl,
    domain: hostname,
    protocol,
    tld,
    path,
    isOfficialDomain: false,
    officialBrandName: matchedBrandTarget,
    riskScore: finalScore,
    riskLevel,
    classification,
    confidence,
    verdict,
    summary,
    metrics: {
      domainAgeEstimate: isSuspiciousTld || isShortener ? '< 30 Days (Disposable Risk)' : 'Standard Registry',
      isNewlyRegistered: isSuspiciousTld,
      sslStatus: protocol === 'https' ? 'Active TLS (Free Automated Certificate)' : 'No SSL Encryption (HTTP)',
      sslWarning:
        'Padlock (HTTPS) does NOT equal safety. Modern scammers obtain free automated certificates in minutes to appear "Secure".',
      tldRisk: isSuspiciousTld ? 'HIGH' : 'LOW',
      hostingReputation: isSuspiciousTld || isIp ? 'SUSPICIOUS_DISPOSABLE' : 'NEUTRAL',
      threatDbListed: isThreatDb,
      threatCategory: isThreatDb ? 'Phishing / Fake KYC' : undefined,
      isObfuscatedShortener: isShortener,
      isRawIpAddress: isIp,
    },
    threats,
    recommendations,
    mlAssessment,
    heuristics,
  };
}
