import { describe, expect, it } from 'vitest';
import { detectScript, normalizeTextForInspection } from '../multilingual.js';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 4 Multilingual & Hinglish NLP Engine', () => {
  it('correctly detects Devanagari script ratio', () => {
    const hindiText = 'आपका खाता बंद कर दिया जाएगा';
    const analysis = detectScript(hindiText);

    expect(analysis.script).toBe('DEVANAGARI');
    expect(analysis.devanagariRatio).toBeGreaterThan(0.8);
  });

  it('detects Hinglish candidate phrasing in Latin script', () => {
    const hinglish = 'Aapka account band ho jayega turant paise wapas karo';
    const analysis = detectScript(hinglish);

    expect(analysis.script).toBe('LATIN');
    expect(analysis.isHinglishCandidate).toBe(true);
  });

  it('normalizes NFKC unicode lookalikes correctly', () => {
    // Full-width latin characters
    const fullWidth = 'ＯＴＰ';
    const normalized = normalizeTextForInspection(fullWidth);
    expect(normalized).toBe('OTP');
  });

  it('scores Hinglish scam with exact parity to English counterparts', () => {
    const hinglishScam = 'Aapka account band ho jayega. Turant OTP share karein.';
    const result = analyzeMessage(hinglishScam);

    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.riskLevel).toBe('HIGH');

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('OTP_REQUEST');
  });

  it('fires rules for pure Devanagari Hindi scam message', () => {
    const hindiScam = 'आपका खाता बंद कर दिया जाएगा तुरंत ओटीपी भेजें';
    const result = analyzeMessage(hindiScam);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('OTP_REQUEST');
    expect(result.riskLevel).toBe('HIGH');
  });
});
