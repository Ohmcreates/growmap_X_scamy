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

  describe('Draggable Forensic Magnifier — Tri-Color Glow & Optical Zoom', () => {
    it('evaluates High Risk SBI KYC scam text and triggers RED GLOW classification', async () => {
      const { evaluateLensThreat } = await import('../magnifier.js');
      const analysis = evaluateLensThreat(DEMO_SAMPLES.sbiKyc, true);

      expect(analysis.riskLevel).toBe('HIGH');
      expect(analysis.score).toBeGreaterThanOrEqual(90);
      expect(analysis.signature).toContain('TROJAN.BANKER');
      expect(analysis.c2Server).toContain('UNAPPROVED_C2');
      expect(analysis.breakdown.length).toBeGreaterThan(0);
    });

    it('evaluates E-Challan fine spoof and triggers RED GLOW with spoof signature', async () => {
      const { evaluateLensThreat } = await import('../magnifier.js');
      const analysis = evaluateLensThreat('URGENT: Traffic Police Challan pending! Pay immediately at http://echallan.redirectme.net');

      expect(analysis.riskLevel).toBe('HIGH');
      expect(analysis.signature).toBe('EXPLOIT.MPARIVAHAN.SPOOF');
      expect(analysis.c2Server).toContain('echallan.redirectme.net');
    });

    it('evaluates unverified links / medium patterns and triggers YELLOW GLOW', async () => {
      const { evaluateLensThreat } = await import('../magnifier.js');
      const analysis = evaluateLensThreat('Please update and verify your profile at external website', true);

      expect(analysis.riskLevel).toBe('MEDIUM');
      expect(analysis.signature).toBe('HEURISTIC.LOOKALIKE.UNVERIFIED');
    });

    it('evaluates benign official notifications and triggers GREEN GLOW', async () => {
      const { evaluateLensThreat } = await import('../magnifier.js');
      const analysis = evaluateLensThreat(DEMO_SAMPLES.legitimate, false);

      expect(analysis.riskLevel).toBe('LOW');
      expect(analysis.hasThreat).toBe(false);
      expect(analysis.signature).toBe('0 / 16 MALWARE VECTORS FIRED');
    });

    it('generates optical zoom snippet with highlighted scam marks', async () => {
      const { generateZoomSnippet } = await import('../magnifier.js');
      const highSnippet = generateZoomSnippet('Your SBI account blocked today! Click http://sbi-update.xyz', 'HIGH');

      expect(highSnippet).toContain('zoom-mark-red');
      expect(highSnippet).toContain('blocked today');

      const cleanSnippet = generateZoomSnippet('Official and safe transaction verified', 'LOW');
      expect(cleanSnippet).toContain('zoom-mark-green');
    });

    it('removes magnifying glass and dock bar on the main website workspace view', async () => {
      const { shouldDisplayMagnifier } = await import('../router.js');

      // The magnifying glass is active on the landing page
      expect(shouldDisplayMagnifier('landing')).toBe(true);

      // The magnifying glass is removed in the main website workspace and auth views
      expect(shouldDisplayMagnifier('workspace')).toBe(false);
      expect(shouldDisplayMagnifier('login')).toBe(false);
    });
  });
});
