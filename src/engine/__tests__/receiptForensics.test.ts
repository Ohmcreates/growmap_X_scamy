import { describe, expect, it } from 'vitest';
import { analyzePaymentReceiptText, validateUpiUtr } from '../receiptForensics.js';

describe('Scam Spotter — Phase 10 Payment Receipt Forensics', () => {
  it('validates 12-digit numeric Indian banking UTR format', () => {
    expect(validateUpiUtr('429182918291')).toBe(true);
    expect(validateUpiUtr('918234')).toBe(false); // too short
    expect(validateUpiUtr('429182918291A')).toBe(false); // contains letter
  });

  it('flags fake receipt with format mismatch on invalid transaction ref', () => {
    const text = 'Payment successful of Rs 5,000. Ref No: TXN-ABC-99. Paid already, dispatch now.';
    const analysis = analyzePaymentReceiptText(text);

    expect(analysis.isUtrValid).toBe(false);
    expect(analysis.formatMismatch).toBe(true);
    expect(analysis.pressureDetected).toBe(true);
    const ruleIds = analysis.firedRules.map((r) => r.ruleId);
    expect(ruleIds).toContain('RECEIPT_FORMAT_MISMATCH');
    expect(ruleIds).toContain('PRESSURE_AFTER_RECEIPT');
  });

  it('flags missing transaction reference on unverified receipt claims', () => {
    const text = 'Transferred Rs 1,500 to your GPay account. Please send the goods immediately.';
    const analysis = analyzePaymentReceiptText(text);

    expect(analysis.missingReference).toBe(true);
    const ruleIds = analysis.firedRules.map((r) => r.ruleId);
    expect(ruleIds).toContain('RECEIPT_MISSING_REFERENCE');
  });
});
