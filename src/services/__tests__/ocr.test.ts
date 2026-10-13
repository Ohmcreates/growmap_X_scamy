import { describe, expect, it } from 'vitest';
import { evaluateOcrConfidence } from '../ocr.js';

describe('Scam Spotter — Phase 1 Feature 5: Screenshot OCR Engine', () => {
  it('identifies high confidence OCR results with zero warning notices', () => {
    const text = 'Dear SBI customer, your account will be blocked. Share your OTP immediately.';
    const conf = evaluateOcrConfidence(text, 88);

    expect(conf.lowConfidence).toBe(false);
    expect(conf.notice).toBeUndefined();
  });

  it('triggers OCR_LOW_CONFIDENCE notice when confidence falls below 65', () => {
    const text = 'Dear customr ur acnt blcked';
    const conf = evaluateOcrConfidence(text, 54);

    expect(conf.lowConfidence).toBe(true);
    expect(conf.notice).toContain('OCR_LOW_CONFIDENCE');
    expect(conf.notice).toContain('verify and edit');
  });

  it('triggers OCR_LOW_CONFIDENCE when extracted text length is too short', () => {
    const shortText = 'OTP 421';
    const conf = evaluateOcrConfidence(shortText, 80);

    expect(conf.lowConfidence).toBe(true);
    expect(conf.notice).toBeDefined();
  });
});
