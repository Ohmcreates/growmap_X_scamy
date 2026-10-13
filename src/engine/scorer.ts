import { DEFAULT_CONFIG } from './config.js';
import { detectRules } from './detector.js';
import { identifyScamProfile } from './profiles.js';
import {
  EngineConfig,
  RiskLevel,
  RuleBreakdownItem,
  ScanResult,
  UnmatchedRuleItem,
} from './types.js';

export function calculateRiskLevel(score: number, config: EngineConfig = DEFAULT_CONFIG): RiskLevel {
  if (score >= config.thresholds.highMin) return 'HIGH';
  if (score >= config.thresholds.lowMax + 1) return 'MEDIUM';
  return 'LOW';
}

export function analyzeMessage(
  text: string,
  config: EngineConfig = DEFAULT_CONFIG,
  options?: { forceFloorHigh?: boolean }
): ScanResult {
  const trimmed = text.trim();
  const detection = detectRules(trimmed, config);

  // Group fired rules
  const rulesMap = new Map(config.rules.map((r) => [r.id, r]));
  const firedRules = Array.from(detection.firedRuleIds).map((id) => rulesMap.get(id)!);

  // Partition fired rules by group to apply group caps
  const byGroup = new Map<string, typeof firedRules>();
  for (const rule of firedRules) {
    if (!byGroup.has(rule.group)) {
      byGroup.set(rule.group, []);
    }
    byGroup.get(rule.group)!.push(rule);
  }

  const breakdown: RuleBreakdownItem[] = [];
  let rawSum = 0;

  for (const [group, rulesInGroup] of byGroup.entries()) {
    // Sort rules in group by points descending
    rulesInGroup.sort((a, b) => b.points - a.points);

    const cap = config.groupCaps[group as keyof typeof config.groupCaps];

    if (cap !== undefined) {
      // Group has a cap (e.g. credential: 40)
      let groupAwarded = 0;
      for (let i = 0; i < rulesInGroup.length; i++) {
        const rule = rulesInGroup[i];
        const evidence = detection.activeEvidence.filter((e) => e.ruleId === rule.id);

        let awarded = 0;
        let capped = false;

        if (groupAwarded < cap) {
          awarded = Math.min(rule.points, cap - groupAwarded);
          groupAwarded += awarded;
        } else {
          capped = true;
          awarded = 0;
        }

        rawSum += awarded;
        breakdown.push({
          ruleId: rule.id,
          label: rule.label,
          group: rule.group,
          category: rule.category,
          rawPoints: rule.points,
          awardedPoints: awarded,
          cappedByGroup: capped,
          explanation: rule.explanation,
          evidence,
        });
      }
    } else {
      // Uncapped group (e.g. pressure: URGENCY 20 + ACCOUNT_THREAT 15 = 35)
      for (const rule of rulesInGroup) {
        const evidence = detection.activeEvidence.filter((e) => e.ruleId === rule.id);
        rawSum += rule.points;
        breakdown.push({
          ruleId: rule.id,
          label: rule.label,
          group: rule.group,
          category: rule.category,
          rawPoints: rule.points,
          awardedPoints: rule.points,
          cappedByGroup: false,
          explanation: rule.explanation,
          evidence,
        });
      }
    }
  }

  // Sort breakdown items by awardedPoints descending, then rawPoints descending
  breakdown.sort((a, b) => b.awardedPoints - a.awardedPoints || b.rawPoints - a.rawPoints);

  // Apply maximum score cap (100)
  let finalScore = Math.min(config.maxScore, rawSum);
  let floorApplied = false;

  // Floor Rule: forced High if verified malicious indicator is detected
  if (options?.forceFloorHigh && finalScore < config.thresholds.highMin) {
    finalScore = config.thresholds.highMin;
    floorApplied = true;
  }

  const riskLevel = calculateRiskLevel(finalScore, config);

  // Construct headline, summary, and advice
  let headline = '';
  let summary = '';
  let advice = '';

  switch (riskLevel) {
    case 'HIGH':
      headline = 'Several warning signs found.';
      summary = 'Do not respond, do not pay, and do not click anything.';
      advice = 'This message displays classic fraud characteristics. Delete it or report it to your bank and cybercrime authorities.';
      break;
    case 'MEDIUM':
      headline = 'Some warning signs found.';
      summary = 'Verify before you act.';
      advice = 'The message contains questionable elements. Verify through the official phone app or verified company website before responding.';
      break;
    case 'LOW':
    default:
      headline = 'No strong warning signs found.';
      summary = 'This is not a guarantee of safety — stay careful with unexpected requests.';
      advice = 'No immediate red flags were detected. Always remain vigilant with unsolicited messages containing sensitive links or payment requests.';
      break;
  }

  // Unmatched rules for transparency
  const unmatchedRules: UnmatchedRuleItem[] = config.rules
    .filter((r) => !detection.firedRuleIds.has(r.id))
    .map((r) => ({
      ruleId: r.id,
      label: r.label,
      category: r.category,
      points: r.points,
    }));

  const scamProfile = identifyScamProfile(text, detection.firedRuleIds);

  return {
    score: finalScore,
    rawScore: rawSum,
    riskLevel,
    headline,
    summary,
    advice,
    breakdown,
    unmatchedRules,
    allEvidence: detection.evidence,
    activeEvidence: detection.activeEvidence,
    negatedEvidence: detection.negatedEvidence,
    floorApplied,
    scamProfile: scamProfile
      ? {
          id: scamProfile.id,
          name: scamProfile.name,
          description: scamProfile.description,
          keySignals: scamProfile.keySignals,
        }
      : undefined,
    metadata: {
      characterCount: text.length,
      scannedAt: new Date().toISOString(),
      engineVersion: '1.0.0',
      totalChecksRun: config.rules.length,
    },
  };
}
