import { describe, it, expect } from 'vitest';
import { inspectUrlHeuristics } from '../urlHeuristics.js';

describe('Scam Spotter — Production-Ready URL Heuristic Verification Engine', () => {
  describe('Group 1: Structural & Lexical Rules (LEX-01 to LEX-07)', () => {
    it('LEX-01: Direct IP in Hostname (+35)', () => {
      const res = inspectUrlHeuristics('http://192.168.1.1/admin');
      const rule = res.firedRules.find((r) => r.id === 'LEX-01');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(35);
      expect(res.totalScore).toBeGreaterThanOrEqual(35);
    });

    it('LEX-02: The @ Symbol Trick (+30)', () => {
      const res = inspectUrlHeuristics('https://paypal.com@attacker-site.com/login');
      const rule = res.firedRules.find((r) => r.id === 'LEX-02');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(30);
    });

    it('LEX-03: Excessive Subdomain Depth (+20)', () => {
      const res = inspectUrlHeuristics('https://login.secure.update.bank.com.attacker.site/auth');
      const rule = res.firedRules.find((r) => r.id === 'LEX-03');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(20);
    });

    it('LEX-04: Excessive Hyphenation (+15)', () => {
      const res = inspectUrlHeuristics('https://secure-paypal-account-verify.com');
      const rule = res.firedRules.find((r) => r.id === 'LEX-04');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(15);
    });

    it('LEX-05: Abnormal URL Length (+10)', () => {
      const longPath = 'a'.repeat(60);
      const res = inspectUrlHeuristics(`https://example-portal.com/${longPath}`);
      const rule = res.firedRules.find((r) => r.id === 'LEX-05');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(10);
    });

    it('LEX-06: Punycode / Homoglyph Characters (+25)', () => {
      const res = inspectUrlHeuristics('https://xn--pple-43d.com/login');
      const rule = res.firedRules.find((r) => r.id === 'LEX-06');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(25);
    });

    it('LEX-07: Double Slash Redirection (+15)', () => {
      const res = inspectUrlHeuristics('http://legit.com//scam.com/action');
      const rule = res.firedRules.find((r) => r.id === 'LEX-07');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(15);
    });
  });

  describe('Group 2: Semantic & Keyword Rules (SEM-01 to SEM-04)', () => {
    it('SEM-01: Sensitive Action Keywords (+20)', () => {
      const res = inspectUrlHeuristics('https://random-service-portal.net/verify-login-kyc');
      const rule = res.firedRules.find((r) => r.id === 'SEM-01');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(20);
    });

    it('SEM-02: Brand Spoofing / Typosquatting (+40)', () => {
      const res = inspectUrlHeuristics('https://paypal-security-center.xyz');
      const rule = res.firedRules.find((r) => r.id === 'SEM-02');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(40);
    });

    it('SEM-03: Suspicious / Free TLDs (+15)', () => {
      const res = inspectUrlHeuristics('https://cheap-deals.xyz');
      const rule = res.firedRules.find((r) => r.id === 'SEM-03');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(15);
    });

    it('SEM-04: Known URL Shortener (+10)', () => {
      const res = inspectUrlHeuristics('https://bit.ly/claim-prize');
      const rule = res.firedRules.find((r) => r.id === 'SEM-04');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(10);
    });
  });

  describe('Group 3: Domain & Network Intelligence Rules (NET-01 to NET-04)', () => {
    it('NET-01: Newly Registered Domain (NRD) (+35) on ephemeral Dynamic DNS', () => {
      const res = inspectUrlHeuristics('https://mparivahan.redirectme.net/6/RTO.MoRTH');
      const rule = res.firedRules.find((r) => r.id === 'NET-01');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(35);
    });

    it('NET-02: Short Expiration Horizon (+10)', () => {
      const res = inspectUrlHeuristics('https://quick-claim.top');
      const rule = res.firedRules.find((r) => r.id === 'NET-02');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(10);
    });

    it('NET-03: No Valid TLS / Missing HTTPS (+25)', () => {
      const res = inspectUrlHeuristics('http://bank-account-login.com');
      const rule = res.firedRules.find((r) => r.id === 'NET-03');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(25);
    });

    it('NET-04: Free SSL on Financial Impersonation (+15)', () => {
      const res = inspectUrlHeuristics('https://sbi-card-secure.xyz');
      const rule = res.firedRules.find((r) => r.id === 'NET-04');
      expect(rule).toBeDefined();
      expect(rule?.points).toBe(15);
    });
  });

  describe('Thresholds & Risk Scoring (0-25 Low, 26-55 Medium, 56+ High)', () => {
    it('scores official allowlisted domains as 0 / Low Risk (Likely Safe)', () => {
      const res = inspectUrlHeuristics('https://sbi.co.in/portal/login');
      expect(res.totalScore).toBe(0);
      expect(res.riskLevel).toBe('Low Risk');
      expect(res.riskCode).toBe('LOW');
      expect(res.isOfficialAllowlisted).toBe(true);
      expect(res.firedRules).toHaveLength(0);
    });

    it('scores single minor signals within 0–25 as Low Risk', () => {
      const res = inspectUrlHeuristics('https://news-blog.com/verify-newsletter');
      // Only SEM-01 (+20) fired:
      expect(res.totalScore).toBeLessThanOrEqual(25);
      expect(res.riskLevel).toBe('Low Risk');
      expect(res.riskCode).toBe('LOW');
    });

    it('scores intermediate evasion signals within 26–55 as Medium Risk (Suspicious)', () => {
      // Direct IP + non-sensitive path = 35 points (Medium Risk)
      const res = inspectUrlHeuristics('https://192.168.1.50/view');
      expect(res.totalScore).toBeGreaterThanOrEqual(26);
      expect(res.totalScore).toBeLessThanOrEqual(55);
      expect(res.riskLevel).toBe('Medium Risk');
      expect(res.riskCode).toBe('MEDIUM');
    });

    it('scores multi-factor phishing domains at 56+ as High Risk (Likely Phishing / Scam)', () => {
      // http://sbi-kyc-update.xyz/login triggers SEM-02 (+40), SEM-01 (+20), SEM-03 (+15), LEX-04 (+15), NET-03 (+25), NET-01 (+35)
      const res = inspectUrlHeuristics('http://sbi-kyc-update.xyz/login');
      expect(res.totalScore).toBeGreaterThanOrEqual(56);
      expect(res.totalScore).toBe(100); // capped at 100
      expect(res.riskLevel).toBe('High Risk');
      expect(res.riskCode).toBe('HIGH');
    });
  });
});
