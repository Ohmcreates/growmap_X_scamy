export type RuleGroup =
  | 'pressure'
  | 'credential'
  | 'payment'
  | 'payment-trick'
  | 'identity'
  | 'bait'
  | 'link'
  | 'receipt'
  | 'campaign'
  | 'override'
  | 'info';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export interface PatternRule {
  id: string;
  label: string;
  group: RuleGroup;
  points: number;
  patterns: RegExp[];
  negationWindowChars?: number;
  negationPatterns?: RegExp[];
  explanation: string;
  category: string;
  advice?: string;
  phase?: number;
}

export interface MatchEvidence {
  ruleId: string;
  ruleLabel: string;
  group: RuleGroup;
  matchedText: string;
  startIndex: number;
  endIndex: number;
  negated: boolean;
  category: string;
}

export interface RuleBreakdownItem {
  ruleId: string;
  label: string;
  group: RuleGroup;
  category: string;
  rawPoints: number;
  awardedPoints: number;
  cappedByGroup: boolean;
  explanation: string;
  evidence: MatchEvidence[];
}

export interface UnmatchedRuleItem {
  ruleId: string;
  label: string;
  category: string;
  points: number;
}

export interface ScanResult {
  score: number;
  rawScore: number;
  riskLevel: RiskLevel;
  headline: string;
  summary: string;
  advice: string;
  breakdown: RuleBreakdownItem[];
  unmatchedRules: UnmatchedRuleItem[];
  allEvidence: MatchEvidence[];
  activeEvidence: MatchEvidence[];
  negatedEvidence: MatchEvidence[];
  floorApplied: boolean;
  scamProfile?: {
    id: string;
    name: string;
    description: string;
    keySignals: string[];
    advicePayload?: string[];
  };
  metadata: {
    characterCount: number;
    scannedAt: string;
    engineVersion: string;
    totalChecksRun: number;
  };
}

export interface EngineConfig {
  rules: PatternRule[];
  groupCaps: Partial<Record<RuleGroup, number>>;
  thresholds: {
    lowMax: number;    // default 20
    mediumMax: number; // default 44
    highMin: number;   // default 45
  };
  officialDomainAllowlist: string[];
  maxScore: number;    // 100
}
