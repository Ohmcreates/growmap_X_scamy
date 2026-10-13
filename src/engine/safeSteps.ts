import { RiskLevel } from './types.js';

export interface ActionStep {
  id: string;
  verb: string;
  instruction: string;
  priority: 'CRITICAL' | 'HIGH' | 'RECOMMENDED';
}

export interface EmergencyActionPlan {
  alreadySharedSteps: string[];
  helplinePhone: string;
  helplineUrl: string;
  portalUrl: string;
  sancharSaathiUrl: string;
}

export const EMERGENCY_PLAN: EmergencyActionPlan = {
  alreadySharedSteps: [
    'Immediately contact your bank branch or the official customer care number on the back of your card to block your account and cards.',
    'Dial 1930 immediately — the National Cyber Crime Reporting Portal helpline for emergency financial fraud freezing within the golden hour.',
    'Register a formal complaint online at cybercrime.gov.in with transaction details and SMS screenshots.',
    'Report the fraudulent sender number on the Government of India Sanchar Saathi (Chakshu) portal at sancharsaathi.gov.in.',
  ],
  helplinePhone: '1930',
  helplineUrl: 'tel:1930',
  portalUrl: 'https://cybercrime.gov.in',
  sancharSaathiUrl: 'https://sancharsaathi.gov.in',
};

export function generateSafeNextSteps(
  firedRuleIds: Set<string>,
  riskLevel: RiskLevel
): ActionStep[] {
  const steps: ActionStep[] = [];

  if (riskLevel === 'LOW') {
    steps.push({
      id: 'VERIFY_CALMLY',
      verb: 'Verify',
      instruction: 'Stay cautious with unexpected messages. Check sender credentials if asking for sensitive details.',
      priority: 'RECOMMENDED',
    });
    steps.push({
      id: 'OFFICIAL_APP',
      verb: 'Use',
      instruction: 'Access services directly through verified mobile apps or typed bookmarks, not unsolicited links.',
      priority: 'RECOMMENDED',
    });
    return steps;
  }

  // Medium or High
  if (firedRuleIds.has('OTP_REQUEST') || firedRuleIds.has('PASSWORD_REQUEST') || firedRuleIds.has('RECEIVE_WITH_PIN')) {
    steps.push({
      id: 'NEVER_SHARE_CREDENTIALS',
      verb: 'Do Not Share',
      instruction: 'Never disclose OTPs, PINs, or passwords. Banks and customer care executives never ask for them.',
      priority: 'CRITICAL',
    });
  }

  if (firedRuleIds.has('SUSPICIOUS_LINK') || firedRuleIds.has('LINK_KNOWN_BAD')) {
    steps.push({
      id: 'DO_NOT_TAP_LINK',
      verb: 'Do Not Tap',
      instruction: 'Do not click or tap any links in this message. To access your account, open the official app directly.',
      priority: 'CRITICAL',
    });
  }

  if (firedRuleIds.has('ACCOUNT_THREAT') || firedRuleIds.has('URGENCY')) {
    steps.push({
      id: 'CALL_OFFICIAL_BANK',
      verb: 'Call',
      instruction: 'Real banks do not suspend accounts via SMS links. Call the verified customer care number printed on the back of your debit card.',
      priority: 'HIGH',
    });
  }

  if (firedRuleIds.has('COLLECT_REQUEST_TRICK') || firedRuleIds.has('QR_TO_RECEIVE')) {
    steps.push({
      id: 'REJECT_PAYMENT_TRICK',
      verb: 'Decline',
      instruction: 'Decline incoming collect requests in PhonePe, GPay, or Paytm. Remember: You NEVER scan QR or enter PIN to receive funds.',
      priority: 'CRITICAL',
    });
  }

  // Universal protection step
  steps.push({
    id: 'BLOCK_AND_REPORT',
    verb: 'Block',
    instruction: 'Block the sender on your device and report the message as spam to your mobile network operator.',
    priority: 'RECOMMENDED',
  });

  return steps;
}
