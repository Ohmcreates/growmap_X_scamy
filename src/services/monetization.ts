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
    name: 'Community Analyst',
    price: '₹0',
    period: 'Standard Free Tier',
    badge: 'Active Default',
    features: [
      'Deterministic rule-based text message scanning',
      'Instant 0–100 explainable risk score',
      'Exact evidence highlighting',
      'Official helpline links (1930 & cybercrime.gov.in)',
      '100% private in-browser analysis',
    ],
    ctaLabel: 'Current Active Tier',
    targetAudience: 'Everyday consumers, students, and family members verifying suspicious messages.',
  },
  {
    id: 'PREMIUM',
    name: 'Analyst Pro',
    price: 'TBD',
    period: 'Pricing Under Evaluation',
    badge: 'In Review',
    features: [
      'Everything in Community Analyst',
      'Deep URL forensics & WHOIS lookups',
      'Screenshot OCR & Payment receipt forensics',
      'Cloud synced scan history audit trail',
      'Priority AI advisory integration',
    ],
    ctaLabel: 'Coming Soon (Under Review)',
    targetAudience: 'Advanced fraud analysts, security teams, and professional researchers.',
  },
  {
    id: 'ENTERPRISE',
    name: 'Institutional / FinTech API',
    price: 'Custom',
    period: 'Volume Licensing',
    badge: 'Enterprise',
    features: [
      'High-throughput REST & Webhook Fraud Scoring API',
      'Banking & UPI in-app SDK integration',
      'Custom institutional fraud rule overrides',
      'Dedicated compliance audit SLA',
    ],
    ctaLabel: 'Inquire for Enterprise',
    targetAudience: 'Banks, NBFCs, Telcos, and Cyber Crime Investigation Cells.',
  },
];

export const UNIT_ECONOMICS = {
  ruleCostPerScan: '₹0.00 (Executed in-browser via WebAssembly / JavaScript)',
  aiCostPerScan: '₹0.04 (~$0.0005 using Flash model)',
  grossMarginOnPaid: '92% gross margin at ₹99/mo (assuming 15 AI scans/user/mo)',
  breakEvenThreshold: '500 paying Family Guardian subscribers covers full operational costs',
};
