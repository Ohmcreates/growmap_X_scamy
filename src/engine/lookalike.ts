import { ReportingService } from '../services/reporting.js';

export interface UrlAnalysis {
  rawUrl: string;
  cleanUrl: string;
  domain: string;
  startIndex: number;
  endIndex: number;
  isAllowlisted: boolean;
  isSuspicious: boolean;
  reasons: string[];
  lookalikeTarget?: string;
  reputationStatus: 'KNOWN_BAD' | 'NO_KNOWN_REPORTS' | 'UNCHECKED';
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

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'click',
  'club',
  'live',
  'work',
  'gq',
  'cf',
  'tk',
  'ml',
  'cc',
  'rest',
]);

const BRAND_KEYWORDS = [
  'sbi',
  'onlinesbi',
  'hdfc',
  'icici',
  'axis',
  'kotak',
  'pnb',
  'paytm',
  'phonepe',
  'gpay',
  'bhim',
  'aadhaar',
  'pan',
  'incometax',
  'parivahan',
  'mparivahan',
  'echallan',
  'challan',
  'rto',
  'morth',
  'indiapost',
  'delhivery',
  'bluedart',
  'electricity',
  'digilocker',
];

export function levenshteinDistance(a: string, b: string): number {
  const an = a.length;
  const bn = b.length;
  if (an === 0) return bn;
  if (bn === 0) return an;

  const matrix = Array.from({ length: bn + 1 }, (_, i) => [i]);
  for (let j = 0; j <= an; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= bn; i++) {
    for (let j = 1; j <= an; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[bn][an];
}

export function extractAndAnalyzeUrls(
  text: string,
  allowlist: string[] = []
): UrlAnalysis[] {
  // Regex to match URLs with or without http(s), including IP addresses
  const urlRegex = /(?:https?:\/\/)?(?:(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}))(?::\d+)?(?:\/[^\s]*)?/gi;
  const results: UrlAnalysis[] = [];
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(text)) !== null) {
    const rawUrl = match[0];
    const startIndex = match.index;

    // Clean trailing punctuation often caught by regex (periods, commas, parens)
    let cleanUrl = rawUrl.replace(/[.,!?;:()]+$/, '');
    const adjustedEnd = startIndex + cleanUrl.length;

    // If no explicit scheme was present, perform sanity checks to prevent false URL matches
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      // Check if preceded by abbreviation words like "Vehicle no.", "Challan no."
      const precedingText = text.slice(Math.max(0, startIndex - 20), startIndex);
      if (/(?:vehicle|challan|flat|house|room|seat|plot|serial|phone|mobile|order|bill|ticket|case|fir|reg|ref)\s*$/i.test(precedingText)) {
        continue;
      }
      if (/^(?:no|dr|mr|mrs|ms|vs|eg|ie|sr|jr|st)\./i.test(cleanUrl)) {
        continue;
      }
      // If the match ends mid-word right before an alphanumeric character without punctuation or space
      if (adjustedEnd < text.length && /[a-zA-Z0-9]/.test(text[adjustedEnd])) {
        continue;
      }
      // Require at least a known dot in domain and a non-empty domain
      if (!cleanUrl.includes('.')) {
        continue;
      }
    }

    // Parse domain
    let domain = '';
    try {
      const urlWithScheme = cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://')
        ? cleanUrl
        : `http://${cleanUrl}`;
      const parsed = new URL(urlWithScheme);
      domain = parsed.hostname.toLowerCase();
    } catch {
      // Fallback simple domain extractor
      domain = cleanUrl.split('/')[0].split(':')[0].toLowerCase();
    }

    if (!domain) {
      continue;
    }

    // Check allowlist
    const isAllowlisted = (allowlist || []).some(
      (official) => domain === official.toLowerCase() || domain.endsWith(`.${official.toLowerCase()}`)
    );

    const reasons: string[] = [];
    let isSuspicious = false;
    let lookalikeTarget: string | undefined;

    if (isAllowlisted) {
      results.push({
        rawUrl: cleanUrl,
        cleanUrl,
        domain,
        startIndex,
        endIndex: adjustedEnd,
        isAllowlisted: true,
        isSuspicious: false,
        reasons: ['Official institution domain on verified allowlist'],
        reputationStatus: 'NO_KNOWN_REPORTS',
      });
      continue;
    }

    // 1. IP address as host
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      isSuspicious = true;
      reasons.push('IP address used instead of reputable domain name');
    }

    // 2. Shortener domain
    if (COMMON_SHORTENERS.has(domain)) {
      isSuspicious = true;
      reasons.push('URL shortener obscures destination address');
    }

    // 3. Dynamic DNS / free redirection service host
    const matchedDdns = Array.from(DYNAMIC_DNS_DOMAINS).find(
      (ddns) => domain === ddns || domain.endsWith(`.${ddns}`)
    );
    if (matchedDdns) {
      isSuspicious = true;
      reasons.push(`Dynamic DNS or redirection service host (*.${matchedDdns}) frequently abused in phishing campaigns`);
    }

    // 4. Punycode / IDN homograph
    if (domain.includes('xn--')) {
      isSuspicious = true;
      reasons.push('Punycode character encoding (potential homoglyph attack)');
    }

    // 5. '@' sign inside URL (browser authentication redirect trick)
    if (cleanUrl.includes('@')) {
      isSuspicious = true;
      reasons.push('@ symbol in link may deceive destination routing');
    }

    // 6. Suspicious or cheap TLD
    const tld = domain.split('.').pop() || '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      isSuspicious = true;
      reasons.push(`Suspicious top-level domain (.${tld}) frequently used in scams`);
    }

    // 7. Brand or Authority name in unofficial domain (e.g. sbi-kyc-update.xyz or mparivahan.redirectme.net)
    for (const brand of BRAND_KEYWORDS) {
      if (domain.includes(brand)) {
        isSuspicious = true;
        lookalikeTarget = brand.toUpperCase();
        reasons.push(`Brand / Authority name "${brand.toUpperCase()}" appears in unofficial domain`);
        break;
      }
    }

    // 8. Lookalike domain check (Levenshtein distance 1-2 against official domains)
    if (!lookalikeTarget) {
      const sld = domain.split('.')[0];
      for (const official of (allowlist || [])) {
        const officialSld = official.split('.')[0];
        const dist = levenshteinDistance(sld, officialSld);
        if (dist > 0 && dist <= 2 && Math.abs(sld.length - officialSld.length) <= 2) {
          isSuspicious = true;
          lookalikeTarget = official;
          reasons.push(`Domain closely mimics official domain "${official}" (typosquatting)`);
          break;
        }
      }
    }

    // 9. Multiple hyphens or excessive subdomains
    if ((domain.match(/-/g) || []).length >= 2) {
      isSuspicious = true;
      reasons.push('Multiple hyphens in domain name (common phishing pattern)');
    }

    // 10. Check threat intelligence database for known bad domain
    try {
      const knownBad = ReportingService.getKnownBadIndicators();
      const inThreatDb = knownBad.some(
        (r) => r.type === 'DOMAIN' && (domain === r.normalizedValue || domain.endsWith(`.${r.normalizedValue}`))
      );
      if (inThreatDb) {
        isSuspicious = true;
        reasons.push('Confirmed malicious domain in verified cybercrime threat intelligence feed');
      }
    } catch {}

    results.push({
      rawUrl: cleanUrl,
      cleanUrl,
      domain,
      startIndex,
      endIndex: adjustedEnd,
      isAllowlisted: false,
      isSuspicious,
      reasons: reasons.length > 0 ? reasons : ['Unverified external web address'],
      lookalikeTarget,
      reputationStatus: isSuspicious ? 'KNOWN_BAD' : 'NO_KNOWN_REPORTS',
    });
  }

  return results;
}
