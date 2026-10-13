export interface TestCase {
  id: string;
  category: 'SCAM' | 'BENIGN';
  text: string;
  expectedMinRisk?: 'LOW' | 'MEDIUM' | 'HIGH';
  expectedMaxRisk?: 'LOW' | 'MEDIUM' | 'HIGH';
  expectedRules?: string[];
  forbiddenRules?: string[];
  description: string;
}

export const BENCHMARK_CORPUS: TestCase[] = [
  // ================= SCAM MESSAGES =================
  {
    id: 'SCAM_01',
    category: 'SCAM',
    text: 'Dear SBI customer, your KYC has expired. Your account will be BLOCKED today. Update immediately at http://sbi-kyc-update.xyz/login and share the OTP you receive to complete verification.',
    expectedMinRisk: 'HIGH',
    expectedRules: ['URGENCY', 'ACCOUNT_THREAT', 'SUSPICIOUS_LINK', 'OTP_REQUEST'],
    description: 'Classic SBI KYC phishing with urgency and OTP request',
  },
  {
    id: 'SCAM_02',
    category: 'SCAM',
    text: 'Dear customer, your electricity power will be disconnected tonight at 9.30 pm from electricity office. Immediately call officer 9876543210.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['ACCOUNT_THREAT', 'URGENCY'],
    description: 'Electricity disconnection coercion threat',
  },
  {
    id: 'SCAM_03',
    category: 'SCAM',
    text: 'Congratulations! You won Rs 50,000 cash reward from PhonePe. Enter your UPI PIN to receive the money in your bank account.',
    expectedMinRisk: 'HIGH',
    expectedRules: ['RECEIVE_WITH_PIN', 'REWARD_BAIT'],
    description: 'UPI PIN entered to receive trick with prize bait',
  },
  {
    id: 'SCAM_04',
    category: 'SCAM',
    text: 'Approve the collect request of Rs 4,999 on Google Pay immediately to receive your cashback refund.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['COLLECT_REQUEST_TRICK', 'URGENCY'],
    description: 'UPI collect request cashback trap',
  },
  {
    id: 'SCAM_05',
    category: 'SCAM',
    text: 'Scan this QR code right now to get your OLX buyer payment transferred into your account.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['QR_TO_RECEIVE'],
    description: 'QR code to receive funds trap',
  },
  {
    id: 'SCAM_06',
    category: 'SCAM',
    text: 'Earn Rs 5000 daily working from home! Simply like YouTube videos. Pay registration fee of Rs 500 to join our VIP team.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['ADVANCE_FEE', 'REWARD_BAIT'],
    description: 'Fake task job advance registration fee scam',
  },
  {
    id: 'SCAM_07',
    category: 'SCAM',
    text: 'Your package is held at customs warehouse due to incorrect address. Pay Rs 25 customs fee within 24 hours: bit.ly/xx12',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['URGENCY', 'SUSPICIOUS_LINK'],
    description: 'Held parcel customs delivery shortlink scam',
  },
  {
    id: 'SCAM_08',
    category: 'SCAM',
    text: 'Urgent: Delhi Police Crime Branch has registered FIR against your Aadhaar for money laundering. Digital arrest order issued. Stay on Skype.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['AUTHORITY_IMPERSONATION', 'URGENCY'],
    description: 'Digital arrest legal intimidation scam',
  },
  {
    id: 'SCAM_09',
    category: 'SCAM',
    text: 'Rs 15,000 transferred by mistake to your account. Return the money immediately to avoid legal action and police complaint.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['WRONG_TRANSFER_PRESSURE'],
    description: 'Accidental transfer panic fraud',
  },
  {
    id: 'SCAM_10',
    category: 'SCAM',
    text: 'HDFC Bank Alert: Your netbanking password has expired. Click http://hdfc-security-update.top to share your password and CVV to reset.',
    expectedMinRisk: 'HIGH',
    expectedRules: ['SUSPICIOUS_LINK', 'PASSWORD_REQUEST'],
    description: 'Credential harvesting for passwords and CVV',
  },
  {
    id: 'SCAM_11',
    category: 'SCAM',
    text: 'Aapka account band ho jayega. Turant OTP share karein nahi toh SIM deactivate ho jayegi.',
    expectedMinRisk: 'HIGH',
    expectedRules: ['ACCOUNT_THREAT', 'URGENCY', 'OTP_REQUEST'],
    description: 'Hinglish account suspension and OTP threat',
  },
  {
    id: 'SCAM_12',
    category: 'SCAM',
    text: 'Loan approved for Rs 10 Lakhs with 0% interest! Deposit processing fee of Rs 3500 immediately to get disbursement.',
    expectedMinRisk: 'MEDIUM',
    expectedRules: ['ADVANCE_FEE', 'URGENCY'],
    description: 'Instant zero-interest loan advance fee scam',
  },

  // ================= BENIGN MESSAGES =================
  {
    id: 'BENIGN_01',
    category: 'BENIGN',
    text: 'Rs 500 debited from A/c XX1234 on 12-Oct. If not you, call the number on the back of your card. Never share OTP with anyone.',
    expectedMaxRisk: 'LOW',
    forbiddenRules: ['OTP_REQUEST', 'ACCOUNT_THREAT'],
    description: 'Authentic bank debit transaction alert with safety advisory',
  },
  {
    id: 'BENIGN_02',
    category: 'BENIGN',
    text: 'Your OTP is 482913 for login to HDFC Bank NetBanking. Valid for 10 minutes. Do not share this OTP with anyone.',
    expectedMaxRisk: 'LOW',
    forbiddenRules: ['OTP_REQUEST'],
    description: 'Standard banking OTP dispatch with negation',
  },
  {
    id: 'BENIGN_03',
    category: 'BENIGN',
    text: 'Dear customer, your SBI Savings account XX4567 has been credited with salary Rs 75,000 on 30-Sep. Check balance on Yono SBI app.',
    expectedMaxRisk: 'LOW',
    description: 'Standard salary credit alert',
  },
  {
    id: 'BENIGN_04',
    category: 'BENIGN',
    text: 'Please visit https://sbi.co.in to download your annual interest certificate.',
    expectedMaxRisk: 'LOW',
    forbiddenRules: ['SUSPICIOUS_LINK'],
    description: 'Official allowlisted banking domain link',
  },
  {
    id: 'BENIGN_05',
    category: 'BENIGN',
    text: 'Hi Dad, flight landed safely in Bangalore. Taking a cab now, see you for dinner at 8pm.',
    expectedMaxRisk: 'LOW',
    description: 'Everyday family text message',
  },
  {
    id: 'BENIGN_06',
    category: 'BENIGN',
    text: 'Reminder: Your dental appointment with Dr. Sharma is scheduled for tomorrow at 4:30 PM. Reply CANCEL if unable to attend.',
    expectedMaxRisk: 'LOW',
    description: 'Standard appointment reminder message',
  },
  {
    id: 'BENIGN_07',
    category: 'BENIGN',
    text: 'Your Swiggy order from Biryani Blues is out for delivery. Delivery partner Manoj will reach you shortly.',
    expectedMaxRisk: 'LOW',
    description: 'Legitimate food delivery status notification',
  },
  {
    id: 'BENIGN_08',
    category: 'BENIGN',
    text: 'Meeting moved to 3pm in room B. Please bring the quarterly report slides.',
    expectedMaxRisk: 'LOW',
    description: 'Workplace coordination text',
  },
  {
    id: 'BENIGN_09',
    category: 'BENIGN',
    text: 'Your electricity bill of Rs 1,420 for consumer number 992819 is due on 25-Oct. Pay via your utility portal or official electricity board app.',
    expectedMaxRisk: 'LOW',
    description: 'Routine utility bill reminder without disconnect threat',
  },
  {
    id: 'BENIGN_10',
    category: 'BENIGN',
    text: 'Google Verification Code: G-829104. Never share your Google verification code with anyone.',
    expectedMaxRisk: 'LOW',
    forbiddenRules: ['OTP_REQUEST'],
    description: 'Google 2FA code delivery with security warning',
  },
];
