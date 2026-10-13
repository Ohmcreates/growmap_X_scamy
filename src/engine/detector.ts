import { DEFAULT_CONFIG, DEFAULT_NEGATION_PATTERNS } from './config.js';
import { extractAndAnalyzeUrls } from './lookalike.js';
import { EngineConfig, MatchEvidence } from './types.js';

export interface DetectionOutput {
  rawText: string;
  evidence: MatchEvidence[];
  activeEvidence: MatchEvidence[];
  negatedEvidence: MatchEvidence[];
  firedRuleIds: Set<string>;
  totalChecksRun: number;
}

export function detectRules(
  text: string,
  config: EngineConfig = DEFAULT_CONFIG
): DetectionOutput {
  const allEvidence: MatchEvidence[] = [];
  const firedRuleIds = new Set<string>();
  const negationWindow = 45;
  const negationPatterns = DEFAULT_NEGATION_PATTERNS;

  // Pre-analyze URLs in the text
  const urlAnalyses = extractAndAnalyzeUrls(text, config.officialDomainAllowlist);
  const allowlistedUrls = urlAnalyses.filter((u) => u.isAllowlisted);
  const suspiciousUrls = urlAnalyses.filter((u) => u.isSuspicious);

  for (const rule of config.rules) {
    // Special handling for SUSPICIOUS_LINK:
    // Only flag if there are actually suspicious URLs, and DO NOT flag allowlisted URLs
    if (rule.id === 'SUSPICIOUS_LINK') {
      for (const suspiciousUrl of suspiciousUrls) {
        allEvidence.push({
          ruleId: rule.id,
          ruleLabel: rule.label,
          group: rule.group,
          category: rule.category,
          matchedText: suspiciousUrl.cleanUrl,
          startIndex: suspiciousUrl.startIndex,
          endIndex: suspiciousUrl.endIndex,
          negated: false,
        });
        firedRuleIds.add(rule.id);
      }
      continue;
    }

    if (rule.id === 'LINK_KNOWN_BAD') {
      // Handled if external or local intelligence flags a known bad link
      const knownBad = suspiciousUrls.filter((u) => u.reputationStatus === 'KNOWN_BAD');
      for (const bad of knownBad) {
        // Only fire if there is an explicit known bad marker
        if (bad.reasons.some((r) => r.includes('Brand name') || r.includes('mimics') || r.includes('Punycode'))) {
          // Keep as SUSPICIOUS_LINK unless explicit floor trigger is set
        }
      }
      continue;
    }

    // Standard pattern matching for other rules
    for (const pattern of rule.patterns) {
      // Ensure global and case-insensitive flags
      const flags = (pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
      const flagsWithI = flags.includes('i') ? flags : `${flags}i`;
      const regex = new RegExp(pattern.source, flagsWithI);

      let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) !== null) {
        const startIndex = match.index;
        const matchedText = match[0];
        const endIndex = startIndex + matchedText.length;

        // Skip zero-length matches to prevent infinite loops
        if (matchedText.length === 0) {
          regex.lastIndex++;
          continue;
        }

        // Check if this match falls entirely inside an allowlisted official URL
        const isInsideAllowlist = allowlistedUrls.some(
          (u) => startIndex >= u.startIndex && endIndex <= u.endIndex
        );
        if (isInsideAllowlist) {
          continue;
        }

        // Check preceding context window for negation keywords
        const windowStart = Math.max(0, startIndex - (rule.negationWindowChars || negationWindow));
        const prefixSlice = text.slice(windowStart, startIndex);

        const isNegated = negationPatterns.some((negPattern) => negPattern.test(prefixSlice));

        const evidence: MatchEvidence = {
          ruleId: rule.id,
          ruleLabel: rule.label,
          group: rule.group,
          category: rule.category,
          matchedText,
          startIndex,
          endIndex,
          negated: isNegated,
        };

        allEvidence.push(evidence);

        if (!isNegated) {
          firedRuleIds.add(rule.id);
        }
      }
    }
  }

  // Split into active and negated evidence
  const activeEvidence = allEvidence.filter((e) => !e.negated);
  const negatedEvidence = allEvidence.filter((e) => e.negated);

  return {
    rawText: text,
    evidence: allEvidence,
    activeEvidence,
    negatedEvidence,
    firedRuleIds,
    totalChecksRun: config.rules.length,
  };
}
