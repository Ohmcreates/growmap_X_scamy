export interface ScamProfile {
  id: string;
  name: string;
  description: string;
  keySignals: string[];
  patterns: RegExp[];
  advicePayload: string[];
}

export const SCAM_PROFILES: ScamProfile[] = [
  {
    id: 'DIGITAL_ARREST',
    name: 'Digital Arrest / Law Enforcement Impersonation',
    description: 'Impersonators posing as Police, CBI, ED, or Customs claiming illegal parcels or money laundering and ordering you to stay on video call.',
    keySignals: ['CBI / Police claim', 'Video call / Skype demand', 'Threat of arrest'],
    patterns: [
      /\b(?:digital\s+arrest|cbi|crime\s+branch|customs\s+seizure|narcotics|dhl\s+parcel\s+drugs|stay\s+on\s+skype|video\s+call\s+statement)\b/i,
    ],
    advicePayload: [
      'Official Indian police and investigative agencies NEVER place citizens under "digital arrest".',
      'Law enforcement officers never interrogate citizens or demand financial clearance over video calls.',
      'Hang up immediately and call the National Cyber Crime Helpline at 1930.',
    ],
  },
  {
    id: 'FAKE_JOB',
    name: 'Fake Job & Task Fraud',
    description: 'Fraudulent work-from-home offers requiring YouTube likes, product ratings, or advance registration fees on Telegram.',
    keySignals: ['Earn Rs 3000-8000 daily', 'No interview', 'Registration / training fee', 'Telegram link'],
    patterns: [
      /\b(?:part[\s-]time\s+job|work\s+from\s+home\s+job|daily\s+income|youtube\s+like|earn\s+daily|telegram\s+task|prepaid\s+task|rating\s+task)\b/i,
    ],
    advicePayload: [
      'Legitimate companies never ask job applicants to pay registration fees or purchase prepaid tasks.',
      'Do not join unknown Telegram groups promising guaranteed daily returns.',
    ],
  },
  {
    id: 'INVESTMENT',
    name: 'High-Yield Investment / Crypto Scam',
    description: 'Promised high returns, insider stock tips, or algorithmic crypto trading via private messaging groups.',
    keySignals: ['Guaranteed 200%+ returns', 'Insider tips', 'VIP WhatsApp group'],
    patterns: [
      /\b(?:guaranteed\s+return|double\s+your\s+money|stock\s+tips|crypto\s+arbitrage|vip\s+trading\s+group|forex\s+robot)\b/i,
    ],
    advicePayload: [
      'All guaranteed-return investment schemes are fraudulent. Check SEBI registration before investing.',
      'Never transfer money to personal UPI accounts for stock trading or mutual funds.',
    ],
  },
  {
    id: 'UTILITY_DISCONNECTION',
    name: 'Electricity / Utility Disconnection Threat',
    description: 'Fake alerts claiming your electricity or gas will be cut tonight unless you call an unofficial number or install remote-access apps.',
    keySignals: ['Power disconnected at 9:30 PM', 'Call personal mobile number', 'Install APK / AnyDesk'],
    patterns: [
      /\b(?:electricity\s+power\s+will\s+be\s+disconnected|light\s+cut|bill\s+not\s+updated|call\s+electricity\s+officer)\b/i,
    ],
    advicePayload: [
      'State electricity boards send official notices on electricity bills, never via random personal phone numbers.',
      'Never install remote desktop apps (AnyDesk, TeamViewer, QuickSupport) on instruction from callers.',
    ],
  },
  {
    id: 'DELIVERY_CUSTOMS',
    name: 'Held Parcel / Delivery Fee Scam',
    description: 'Phishing SMS claiming your package cannot be delivered due to wrong address, demanding a small ₹25 fee via link.',
    keySignals: ['Package held', 'Update address immediately', 'Pay ₹25 redelivery fee'],
    patterns: [
      /\b(?:package\s+(?:held|could\s+not\s+be\s+delivered|failed)|customs\s+fee|redelivery\s+fee|update\s+delivery\s+address|indiapost|delhivery\s+held)\b/i,
    ],
    advicePayload: [
      'Postal services do not ask for card details via SMS links for failed deliveries.',
      'Track shipments exclusively on official courier websites using your original tracking ID.',
    ],
  },
  {
    id: 'UPI_FRAUD',
    name: 'UPI / Digital Payment Trick',
    description: 'Attempting to deceive victims into entering their UPI PIN, scanning QR codes, or approving collect requests to "receive" funds.',
    keySignals: ['Enter PIN to receive money', 'Approve collect request', 'Scan QR for refund'],
    patterns: [
      /\b(?:upi\s+pin|collect\s+request|scan\s+qr|scan\s+to\s+receive|refund\s+claim)\b/i,
    ],
    advicePayload: [
      'Golden Rule: You NEVER enter your UPI PIN to receive money. UPI PIN is solely for debiting funds.',
      'Reject any incoming collect requests on Google Pay, PhonePe, or Paytm.',
    ],
  },
  {
    id: 'KYC_BANKING',
    name: 'Bank KYC / Account Suspension Scam',
    description: 'Phishing attempts mimicking reputable banks claiming account blockage unless KYC is completed via an unverified link.',
    keySignals: ['KYC expired', 'Account will be blocked', 'Share OTP for verification'],
    patterns: [
      /\b(?:kyc\s+expired|account\s+will\s+be\s+blocked|update\s+kyc|pan\s+card\s+link|(?:sbi|hdfc|icici|pnb|axis|bank)[\s\S]{0,40}(?:kyc|blocked|block|suspend|pan\s*link))\b/i,
    ],
    advicePayload: [
      'Banks will never send SMS links to update KYC. Visit your official bank branch or use the verified app.',
      'Never disclose OTPs to anyone, including persons claiming to be bank employees.',
    ],
  },
  {
    id: 'TRAFFIC_CHALLAN',
    name: 'Fake E-Challan / Traffic Fine Scam',
    description: 'Impersonation of Traffic Police, RTO, or MoRTH claiming a traffic violation or pending e-Challan with a deceptive link to steal funds or netbanking credentials.',
    keySignals: ['Fake e-Challan / Traffic notice', 'Unofficial mParivahan or redirect link', 'Urgent paynow demand', 'Vehicle or Challan number simulation'],
    patterns: [
      /\b(?:e[\s-]*cha[lI1|]{2}an|cha[lI1|]{2}an|traffic\s+(?:police|fine|challan)|mparivahan|parivahan|rto|morth|vehicle\s+no|challan\s+no)\b/i,
    ],
    advicePayload: [
      'Official traffic challans in India are hosted ONLY on the national government portal: https://echallan.parivahan.gov.in.',
      'Indian traffic police and MoRTH never send payment links using .net, .com, or dynamic redirectors like redirectme.net or duckdns.org.',
      'Verify pending challans safely by searching your vehicle registration number on the official Parivahan website or DigiLocker app.',
      'Never enter card details or UPI PIN on links received via SMS.',
    ],
  },
];

export function identifyScamProfile(
  text: string,
  firedRuleIds: Set<string>
): ScamProfile | undefined {
  if (firedRuleIds.size === 0) {
    return undefined;
  }

  let bestProfile: ScamProfile | undefined;
  let maxMatches = 0;

  for (const profile of SCAM_PROFILES) {
    let score = 0;
    for (const pattern of profile.patterns) {
      if (pattern.test(text)) {
        score += 2;
      }
    }

    // Boost score if correlated rules fired
    if (profile.id === 'UPI_FRAUD' && (firedRuleIds.has('RECEIVE_WITH_PIN') || firedRuleIds.has('COLLECT_REQUEST_TRICK') || firedRuleIds.has('QR_TO_RECEIVE'))) {
      score += 5;
    }
    if (profile.id === 'KYC_BANKING' && (firedRuleIds.has('ACCOUNT_THREAT') && firedRuleIds.has('OTP_REQUEST'))) {
      score += 4;
    }
    if (
      profile.id === 'DIGITAL_ARREST' &&
      firedRuleIds.has('AUTHORITY_IMPERSONATION') &&
      /\b(?:digital\s+arrest|cbi|crime\s+branch|customs\s+seizure|narcotics|skype|video\s+call|warrant)\b/i.test(text)
    ) {
      score += 5;
    }
    if (profile.id === 'UTILITY_DISCONNECTION' && /\b(?:electricity|bijli|power|gas|utility)\b/i.test(text)) {
      score += 5;
    }
    if (profile.id === 'DELIVERY_CUSTOMS' && /\b(?:package|parcel|delivery|courier|fedex|india\s+post|dhl)\b/i.test(text)) {
      score += 5;
    }

    if (score > maxMatches && score >= 2) {
      maxMatches = score;
      bestProfile = profile;
    }
  }

  return bestProfile;
}
