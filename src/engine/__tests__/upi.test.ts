import { describe, expect, it } from 'vitest';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 2 UPI & Payment Safety Engine', () => {
  it('detects UPI PIN trick to receive money (RECEIVE_WITH_PIN)', () => {
    const msg = 'Enter your UPI PIN to receive the prize of Rs 50,000 in your account.';
    const result = analyzeMessage(msg);

    expect(result.score).toBeGreaterThanOrEqual(40);
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('RECEIVE_WITH_PIN');
  });

  it('detects UPI Collect Request exploit (COLLECT_REQUEST_TRICK)', () => {
    const msg = 'Approve the collect request in PhonePe to get your refund of Rs 1,499.';
    const result = analyzeMessage(msg);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('COLLECT_REQUEST_TRICK');
    expect(result.score).toBeGreaterThanOrEqual(30);
  });

  it('detects QR Code scan to receive money fallacy (QR_TO_RECEIVE)', () => {
    const msg = 'Scan this QR code on Google Pay to receive payment for your OLX item.';
    const result = analyzeMessage(msg);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('QR_TO_RECEIVE');
    expect(result.score).toBeGreaterThanOrEqual(30);
  });

  it('detects accidental transfer pressure (WRONG_TRANSFER_PRESSURE)', () => {
    const msg = 'Rs 10,000 transferred by mistake to your account. Please refund immediately or face police complaint.';
    const result = analyzeMessage(msg);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('WRONG_TRANSFER_PRESSURE');
    expect(firedIds).toContain('URGENCY');
  });

  it('detects advance fee / processing charge scams (ADVANCE_FEE)', () => {
    const msg = 'Your loan of Rs 5,00,000 is approved. Pay registration fee of Rs 2,500 to release disbursement.';
    const result = analyzeMessage(msg);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ADVANCE_FEE');
  });
});
