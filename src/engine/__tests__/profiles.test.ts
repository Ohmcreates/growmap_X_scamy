import { describe, expect, it } from 'vitest';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 5 Scam Typology Profiler', () => {
  it('identifies Digital Arrest scam archetype', () => {
    const text = 'Urgent: CBI and Police cyber branch issued a digital arrest warrant against your Aadhaar. Stay on Skype video call statement.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('DIGITAL_ARREST');
  });

  it('identifies Fake Job & Task Fraud archetype', () => {
    const text = 'Part-time work from home job! Earn daily Rs 5000 by YouTube like tasks. Join our telegram task channel.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('FAKE_JOB');
  });

  it('identifies High-Yield Investment archetype', () => {
    const text = 'Guaranteed return of 300% in 7 days! Join VIP trading group for insider stock tips and crypto arbitrage.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('INVESTMENT');
  });

  it('identifies Electricity / Utility Disconnection archetype', () => {
    const text = 'Dear customer, your electricity power will be disconnected tonight at 9.30 PM. Call electricity officer immediately.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('UTILITY_DISCONNECTION');
  });

  it('identifies Held Delivery / Customs redelivery archetype', () => {
    const text = 'Your package could not be delivered due to wrong address. Pay Rs 25 customs fee within 24 hours to update address.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('DELIVERY_CUSTOMS');
  });

  it('identifies UPI PIN / Collect exploit archetype', () => {
    const text = 'Enter your UPI PIN on PhonePe to receive prize reward of Rs 25,000.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('UPI_FRAUD');
  });

  it('identifies Bank KYC / Account blockage archetype', () => {
    const text = 'Dear SBI customer, your KYC has expired and account will be blocked today. Share your OTP to update.';
    const result = analyzeMessage(text);
    expect(result.scamProfile?.id).toBe('KYC_BANKING');
  });
});
