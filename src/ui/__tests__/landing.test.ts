import { describe, it, expect } from 'vitest';
import { analyzeMessage } from '../../engine/scorer.js';
import { generateSafeNextSteps } from '../../engine/safeSteps.js';
import { BUILD_STAGES } from '../progressiveBuild.js';
import { DEMO_SAMPLES } from '../liveDemo.js';

describe('Scam Spotter — Editorial Landing Page & Components', () => {
  it('Progressive Construction has all 7 architectural stages', () => {
    expect(BUILD_STAGES.length).toBe(7);
    expect(BUILD_STAGES.map((s) => s.step)).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(BUILD_STAGES[0].title).toBe('The Alignment Line');
    expect(BUILD_STAGES[1].title).toBe('The Page Grid');
    expect(BUILD_STAGES[2].title).toBe('The Content Layout');
    expect(BUILD_STAGES[3].title).toBe('Typography & Hierarchy');
    expect(BUILD_STAGES[4].title).toBe('The Red & Neutral System');
    expect(BUILD_STAGES[5].title).toBe('Scam Detection Interface');
    expect(BUILD_STAGES[6].title).toBe('The Finished Experience');
  });

  it('Live Product Demo: Fictional SBI KYC scam scores 100/100 HIGH RISK with exact breakdown', () => {
    const text = DEMO_SAMPLES.sbiKyc;
    const result = analyzeMessage(text);

    expect(result.score).toBe(100);
    expect(result.riskLevel).toBe('HIGH');

    const ruleIds = result.breakdown.map((b) => b.ruleId);
    expect(ruleIds).toContain('URGENCY'); // +20
    expect(ruleIds).toContain('ACCOUNT_THREAT'); // +15
    expect(ruleIds).toContain('SUSPICIOUS_LINK'); // +25
    expect(ruleIds).toContain('OTP_REQUEST'); // +40

    const firedIds = new Set(ruleIds);
    const steps = generateSafeNextSteps(firedIds, result.riskLevel);
    expect(steps.length).toBeGreaterThan(0);
    expect(steps.some((s) => s.id === 'NEVER_SHARE_CREDENTIALS')).toBe(true);
  });

  it('Live Product Demo: Legitimate bank SMS receives LOW risk score', () => {
    const text = DEMO_SAMPLES.legitimate;
    const result = analyzeMessage(text);
    expect(result.score).toBeLessThan(30);
    expect(result.riskLevel).toBe('LOW');
  });
});
