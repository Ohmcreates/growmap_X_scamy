import { describe, expect, it } from 'vitest';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 1 Core Rule Engine', () => {
  it('identifies the canonical fictional SBI KYC scam with exact 100/100 High score', () => {
    const sbiScam =
      'Dear SBI customer, your KYC has expired. Your account will be BLOCKED today. Update immediately at http://sbi-kyc-update.xyz/login and share the OTP you receive to complete verification.';

    const result = analyzeMessage(sbiScam);

    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('HIGH');

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('SUSPICIOUS_LINK');
    expect(firedIds).toContain('OTP_REQUEST');

    // Check individual points
    const urgency = result.breakdown.find((b) => b.ruleId === 'URGENCY');
    const threat = result.breakdown.find((b) => b.ruleId === 'ACCOUNT_THREAT');
    const link = result.breakdown.find((b) => b.ruleId === 'SUSPICIOUS_LINK');
    const otp = result.breakdown.find((b) => b.ruleId === 'OTP_REQUEST');

    expect(urgency?.awardedPoints).toBe(20);
    expect(threat?.awardedPoints).toBe(15);
    expect(link?.awardedPoints).toBe(25);
    expect(otp?.awardedPoints).toBe(40);
  });

  it('correctly handles negation in legitimate OTP delivery messages (does not fire OTP_REQUEST)', () => {
    const benignOtp = 'Your OTP is 482913. Do not share it with anyone.';
    const result = analyzeMessage(benignOtp);

    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    expect(result.breakdown.length).toBe(0);
    expect(result.negatedEvidence.length).toBeGreaterThan(0);
  });

  it('does not flag official allowlisted bank domains', () => {
    const officialMsg = 'Visit https://sbi.co.in for details regarding your branch.';
    const result = analyzeMessage(officialMsg);

    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).not.toContain('SUSPICIOUS_LINK');
  });

  it('detects suspicious shortened links', () => {
    const shortenerMsg = 'Click bit.ly/x9A to update KYC';
    const result = analyzeMessage(shortenerMsg);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('SUSPICIOUS_LINK');
    expect(result.score).toBeGreaterThanOrEqual(25);
  });

  it('scores completely benign message as 0 / Low', () => {
    const benign = 'Lunch at 1pm?';
    const result = analyzeMessage(benign);

    expect(result.score).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    expect(result.breakdown).toHaveLength(0);
  });

  it('enforces credential group cap when both OTP and password requests appear', () => {
    const credCombo = 'Share your OTP and password immediately';
    const result = analyzeMessage(credCombo);

    // Credential group cap is 40. Urgency adds 20. Total = 60 / High.
    expect(result.score).toBe(60);
    expect(result.riskLevel).toBe('HIGH');

    const otp = result.breakdown.find((b) => b.ruleId === 'OTP_REQUEST');
    const pwd = result.breakdown.find((b) => b.ruleId === 'PASSWORD_REQUEST');

    expect(otp).toBeDefined();
    expect(pwd).toBeDefined();

    // One must have 40 awarded, and the other must have 0 awarded with cappedByGroup true
    const awardedCredPoints = (otp?.awardedPoints || 0) + (pwd?.awardedPoints || 0);
    expect(awardedCredPoints).toBe(40);

    const cappedItem = result.breakdown.find((b) => b.cappedByGroup);
    expect(cappedItem).toBeDefined();
    expect(cappedItem?.awardedPoints).toBe(0);
  });

  it('counts repeated phrases once for scoring (idempotent invariant)', () => {
    const repeated = 'Urgent! Urgent! Urgent! Urgent! Urgent!';
    const result = analyzeMessage(repeated);

    expect(result.score).toBe(20);
    expect(result.riskLevel).toBe('LOW');
    expect(result.breakdown).toHaveLength(1);
    expect(result.breakdown[0].ruleId).toBe('URGENCY');
    // But multiple evidence occurrences are captured
    expect(result.breakdown[0].evidence.length).toBeGreaterThan(1);
  });
});
