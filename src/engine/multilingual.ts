export type DetectedScript = 'LATIN' | 'DEVANAGARI' | 'MIXED' | 'UNKNOWN';

export interface ScriptAnalysis {
  script: DetectedScript;
  devanagariRatio: number;
  latinRatio: number;
  totalChars: number;
  isHinglishCandidate: boolean;
  supportNotice?: string;
}

export function detectScript(text: string): ScriptAnalysis {
  let devanagariCount = 0;
  let latinCount = 0;
  let totalLetterCount = 0;

  for (const char of text) {
    const code = char.codePointAt(0) || 0;
    // Devanagari Unicode Block: U+0900 to U+097F
    if (code >= 0x0900 && code <= 0x097f) {
      devanagariCount++;
      totalLetterCount++;
    } else if ((code >= 0x0041 && code <= 0x005a) || (code >= 0x0061 && code <= 0x007a)) {
      latinCount++;
      totalLetterCount++;
    }
  }

  if (totalLetterCount === 0) {
    return {
      script: 'UNKNOWN',
      devanagariRatio: 0,
      latinRatio: 0,
      totalChars: text.length,
      isHinglishCandidate: false,
    };
  }

  const devanagariRatio = devanagariCount / totalLetterCount;
  const latinRatio = latinCount / totalLetterCount;

  let script: DetectedScript = 'LATIN';
  let isHinglishCandidate = false;
  let supportNotice: string | undefined;

  if (devanagariRatio > 0.6) {
    script = 'DEVANAGARI';
  } else if (devanagariRatio > 0.2 && latinRatio > 0.2) {
    script = 'MIXED';
  } else {
    script = 'LATIN';
    // If predominantly Latin, could be English or Hinglish
    // Check for common Hinglish markers
    if (/\b(?:karein|karo|bhejo|aaj|turant|paise|khata|band|aapka|humara)\b/i.test(text)) {
      isHinglishCandidate = true;
    }
  }

  return {
    script,
    devanagariRatio,
    latinRatio,
    totalChars: text.length,
    isHinglishCandidate,
    supportNotice,
  };
}

/**
 * Normalizes input text using Unicode NFKC (Compatibility Decomposition,
 * followed by Canonical Composition) while keeping character offsets safe.
 */
export function normalizeTextForInspection(text: string): string {
  // NFKC decomposes full-width characters, ligature quirks, etc.
  return text.normalize('NFKC');
}
