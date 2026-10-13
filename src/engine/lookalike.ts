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
  allowlist: string[]
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

    // Check allowlist
    const isAllowlisted = allowlist.some(
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

    // 3. Punycode / IDN homograph
    if (domain.includes('xn--')) {
      isSuspicious = true;
      reasons.push('Punycode character encoding (potential homoglyph attack)');
    }

    // 4. '@' sign inside URL (browser authentication redirect trick)
    if (cleanUrl.includes('@')) {
      isSuspicious = true;
      reasons.push('@ symbol in link may deceive destination routing');
    }

    // 5. Suspicious or cheap TLD
    const tld = domain.split('.').pop() || '';
    if (SUSPICIOUS_TLDS.has(tld)) {
      isSuspicious = true;
      reasons.push(`Suspicious top-level domain (.${tld}) frequently used in scams`);
    }

    // 6. Brand name in unofficial domain (e.g. sbi-kyc-update.xyz or sbi.security-alert.com)
    for (const brand of BRAND_KEYWORDS) {
      if (domain.includes(brand)) {
        isSuspicious = true;
        lookalikeTarget = brand.toUpperCase();
        reasons.push(`Brand name "${brand.toUpperCase()}" appears in unofficial domain`);
        break;
      }
    }

    // 7. Lookalike domain check (Levenshtein distance 1-2 against official domains)
    if (!lookalikeTarget) {
      const sld = domain.split('.')[0];
      for (const official of allowlist) {
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

    // 8. Multiple hyphens or excessive subdomains
    if ((domain.match(/-/g) || []).length >= 2) {
      isSuspicious = true;
      reasons.push('Multiple hyphens in domain name (common phishing pattern)');
    }

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
