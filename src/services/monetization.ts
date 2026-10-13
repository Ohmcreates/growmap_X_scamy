export interface PricingTier {
  id: string;
  name: string;
  price: string;
  period: string;
  badge?: string;
  features: string[];
  ctaLabel: string;
  targetAudience: string;
}

export const PRICING_TIERS: PricingTier[] = [
  {
    id: 'FREE',
    name: 'Community / Free',
    price: '₹0',
    period: 'Forever free',
    features: [
      'Pure deterministic rule scanning',
      'Instant 0–100 explainable score',
      'Exact evidence highlighting',
      'Safe next steps & helpline links',
      '100% private offline analysis',
      'Up to 5 daily scans',
    ],
    ctaLabel: 'Active Plan',
    targetAudience: 'General public, students, and first-time digital payment users.',
  },
  {
    id: 'PREMIUM',
    name: 'Family Guardian',
    price: '₹99',
    period: 'per month (or ₹799/year)',
    badge: 'Most Popular',
    features: [
      'Everything in Community tier',
      'Guarded AI Second Opinion analysis',
      'Unlimited scans & 50-entry history',
      'URL reputation & threat feed checks',
      'Hindi / Hinglish multilingual engine',
      'Exportable fraud evidence reports',
    ],
    ctaLabel: 'Upgrade to Guardian',
    targetAudience: 'Families protecting elderly parents and non-tech-savvy relatives.',
  },
  {
    id: 'ENTERPRISE',
    name: 'FinTech / Institutional',
    price: 'Custom',
    period: 'per 1,000 API scans',
    features: [
      'REST & Webhook Fraud Scoring API',
      'White-label embed for Banking / UPI apps',
      'Real-time phishing feed ingestion',
      'Custom institutional rule overrides',
      'Dedicated compliance SLA & audit logs',
    ],
    ctaLabel: 'Contact Sales',
    targetAudience: 'Banks (SBI, HDFC), NBFCs, Telcos, and Consumer Protection NGOs.',
  },
];

export const UNIT_ECONOMICS = {
  ruleCostPerScan: '₹0.00 (Executed in-browser via WebAssembly / JavaScript)',
  aiCostPerScan: '₹0.04 (~$0.0005 using Flash model)',
  grossMarginOnPaid: '92% gross margin at ₹99/mo (assuming 15 AI scans/user/mo)',
  breakEvenThreshold: '500 paying Family Guardian subscribers covers full operational costs',
};
