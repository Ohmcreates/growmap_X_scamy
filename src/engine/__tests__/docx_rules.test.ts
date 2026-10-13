import { describe, it, expect } from 'vitest';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Official Rules & Use Cases from Scam_Spotter_Rules.docx', () => {
  it('Case 1: The Bank / KYC Scam should score 100 points (HIGH RISK)', () => {
    const text = 'Dear Customer, your HDFC bank account will be blocked today due to incomplete KYC. Update immediately at http://hdfc-kyc-alert.xyz and enter OTP to verify.';
    const result = analyzeMessage(text);
    console.log('Case 1 Score:', result.score, 'Breakdown:', result.breakdown.map(b => `${b.ruleId} (+${b.awardedPoints})`));
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('HIGH');
  });

  it('Case 2: The Failed Package Delivery Scam should score 100 points (HIGH RISK)', () => {
    const text = 'India Post: Your package delivery failed due to unpaid customs fee of Rs 5. Pay within 12 hours to reschedule delivery here: http://bit.ly/indpst-fee';
    const result = analyzeMessage(text);
    console.log('Case 2 Score:', result.score, 'Breakdown:', result.breakdown.map(b => `${b.ruleId} (+${b.awardedPoints})`));
    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('HIGH');
  });

  it('Case 3: Government / Traffic Fine Scam should score at least 60 points (HIGH RISK)', () => {
    const text = 'Traffic Police: You have a pending E-Challan of Rs 2000. Pay immediately at http://echallan-parivahan-gov.in.xyz to avoid legal action.';
    const result = analyzeMessage(text);
    console.log('Case 3 Score:', result.score, 'Breakdown:', result.breakdown.map(b => `${b.ruleId} (+${b.awardedPoints})`));
    expect(result.score).toBe(60);
    expect(result.riskLevel).toBe('HIGH');
  });

  it('Case 4: The Wrong Number (Pig Butchering) Scam should score 15 points (LOW RISK)', () => {
    const text = 'Hi Dr. Sharma, are we still meeting for golf tomorrow at the club?';
    const result = analyzeMessage(text);
    console.log('Case 4 Score:', result.score, 'Breakdown:', result.breakdown.map(b => `${b.ruleId} (+${b.awardedPoints})`));
    expect(result.score).toBe(15);
    expect(result.riskLevel).toBe('LOW');
  });
});
