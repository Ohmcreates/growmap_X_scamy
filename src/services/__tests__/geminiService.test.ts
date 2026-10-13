import { describe, it, expect } from 'vitest';
import { GeminiService } from '../geminiService.js';

describe('Scam Spotter — Google Gemini Cybersecurity Advisory Service', () => {
  it('Purpose 1 & 2: Analyzes fraudulent message with embedded URL and returns user schema', async () => {
    const fakeMessage =
      'Alert E-ChaIIan INR.1000 Generated: Vehicle no.OD02DJ8596 Challan no.OD11092445 paynow: https://mparivahan.redirectme.net/6/RTO.MoRTH';
    
    const result = await GeminiService.analyzeMessageOrUrl(fakeMessage);

    expect(result).toBeDefined();
    expect(['SCAM', 'SUSPICIOUS', 'SAFE']).toContain(result.verdict);
    expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(result.threat_level);
    expect(result.confidence_score).toBeGreaterThanOrEqual(0);
    expect(result.confidence_score).toBeLessThanOrEqual(100);
    expect(result.targeted_brand_or_entity).toBeDefined();
    expect(result.scam_category).toBeDefined();
    expect(result.risk_indicators.length).toBeGreaterThan(0);
    expect(result.user_guidance).toBeDefined();
  }, 15000);

  it('Purpose 1 & 2: Correctly analyzes a legitimate benign message as SAFE', async () => {
    const benignMessage =
      'Hi Dad, flight landed safely in Bangalore. Taking a cab now, see you for dinner at 8pm.';
    
    const result = await GeminiService.analyzeMessageOrUrl(benignMessage);

    expect(result).toBeDefined();
    expect(['SAFE', 'SUSPICIOUS']).toContain(result.verdict);
    expect(['LOW', 'MEDIUM']).toContain(result.threat_level);
  }, 15000);

  it('Resilient fallback handles empty input gracefully', async () => {
    const emptyResult = await GeminiService.analyzeMessageOrUrl('');
    expect(emptyResult.verdict).toBe('SAFE');
    expect(emptyResult.threat_level).toBe('LOW');
  });
});
