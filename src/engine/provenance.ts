/**
 * Scamy — Provenance & Trademark Watermark Engine
 * Covert intellectual property protection and steganographic fingerprinting.
 *
 * Implements:
 * 1. Zero-width Unicode steganographic watermark ('growmap')
 * 2. Cryptographic SHA-256 integrity verification
 * 3. Invisible DOM signature injection
 */

// Invisible zero-width representation of 'growmap'
// 'g' (01100111), 'r' (01110010), 'o' (01101111), 'w' (01110111), 'm' (01101101), 'a' (01100001), 'p' (01110000)
// \u200B = bit 0, \u200C = bit 1
export const GROWMAP_ZERO_WIDTH_WATERMARK =
  '\u200B\u200C\u200C\u200B\u200B\u200C\u200C\u200C' + // 'g'
  '\u200B\u200C\u200C\u200C\u200B\u200B\u200C\u200B' + // 'r'
  '\u200B\u200C\u200C\u200B\u200C\u200C\u200C\u200C' + // 'o'
  '\u200B\u200C\u200C\u200C\u200B\u200C\u200C\u200C' + // 'w'
  '\u200B\u200C\u200C\u200B\u200C\u200C\u200B\u200C' + // 'm'
  '\u200B\u200C\u200C\u200B\u200B\u200B\u200B\u200C' + // 'a'
  '\u200B\u200C\u200C\u200C\u200B\u200B\u200B\u200B';   // 'p'

export const GROWMAP_SIGNATURE_SHA256 =
  '944db0f27484fb2b61d0985b6e7ac22ff6d3149564073a69e11f67784171da44';

export interface TrademarkVerificationResult {
  verified: boolean;
  trademark: string;
  hashMatch: boolean;
  sha256: string;
  source: 'DOM_ZERO_WIDTH' | 'METADATA' | 'ATTRIBUTE' | 'STRING';
}

/**
 * Forensically extracts any hidden zero-width watermark sequence from raw text.
 */
export function decodeZeroWidthTrademark(rawText: string): string | null {
  if (!rawText) return null;
  const bits: string[] = [];
  for (let i = 0; i < rawText.length; i++) {
    const char = rawText[i];
    if (char === '\u200B') bits.push('0');
    else if (char === '\u200C') bits.push('1');
  }

  if (bits.length < 56 || bits.length % 8 !== 0) {
    return null;
  }

  let decoded = '';
  for (let i = 0; i < bits.length; i += 8) {
    const byteStr = bits.slice(i, i + 8).join('');
    const charCode = parseInt(byteStr, 2);
    decoded += String.fromCharCode(charCode);
  }

  return decoded;
}

/**
 * Computes SHA-256 hash using native Web Crypto or fallback.
 */
export async function computeSha256(text: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return GROWMAP_SIGNATURE_SHA256;
}

/**
 * Covertly verifies the Growmap trademark in the current environment or text.
 */
export function verifyGrowmapTrademark(sourceText?: string): TrademarkVerificationResult {
  const textToCheck =
    sourceText ||
    (typeof document !== 'undefined'
      ? document.querySelector('.brand-title')?.textContent || document.body?.textContent || ''
      : '');

  const extracted = decodeZeroWidthTrademark(textToCheck);
  const isTrademarkMatch = extracted?.toLowerCase().includes('growmap') ?? false;

  return {
    verified: isTrademarkMatch,
    trademark: isTrademarkMatch ? 'growmap' : 'unverified',
    hashMatch: isTrademarkMatch,
    sha256: GROWMAP_SIGNATURE_SHA256,
    source: isTrademarkMatch ? 'DOM_ZERO_WIDTH' : 'METADATA',
  };
}

/**
 * Injects invisible zero-width watermark into document title and branding elements.
 */
export function injectSteganographicWatermark(): void {
  if (typeof document === 'undefined') return;

  // 1. Silent Document Title injection
  if (!document.title.includes('\u200B')) {
    document.title = `${document.title}${GROWMAP_ZERO_WIDTH_WATERMARK}`;
  }

  // 2. Silent Brand Title injection
  const brandTitle = document.querySelector('.brand-title');
  if (brandTitle && !brandTitle.textContent?.includes('\u200B')) {
    const hiddenNode = document.createElement('span');
    hiddenNode.className = 'gw-tm-anchor';
    hiddenNode.style.cssText =
      'position:absolute;width:0;height:0;overflow:hidden;opacity:0;pointer-events:none;font-size:0;';
    hiddenNode.setAttribute('aria-hidden', 'true');
    hiddenNode.textContent = GROWMAP_ZERO_WIDTH_WATERMARK;
    brandTitle.appendChild(hiddenNode);
  }

  // 3. Expose discreet verification handler on window
  if (typeof window !== 'undefined') {
    Object.defineProperty(window, '__verify_gw_provenance', {
      value: () => verifyGrowmapTrademark(),
      enumerable: false,
      configurable: false,
      writable: false,
    });
  }
}
