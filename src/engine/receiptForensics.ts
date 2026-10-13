export interface ReceiptForensicAnalysis {
  utrNumber?: string;
  isUtrValid: boolean;
  amountMismatch: boolean;
  missingReference: boolean;
  formatMismatch: boolean;
  pressureDetected: boolean;
  inconclusiveNotice: string;
  firedRules: { ruleId: string; points: number; reason: string }[];
}

export function validateUpiUtr(utr: string): boolean {
  const cleaned = utr.trim().replace(/\s+/g, '');
  // Standard Indian Banking UTR: exactly 12 numeric digits
  // Formats: [Last digit of year][Julian Day (3 digits)][Hour/Sequence...]
  if (!/^\d{12}$/.test(cleaned)) {
    return false;
  }
  return true;
}

export function analyzePaymentReceiptText(text: string): ReceiptForensicAnalysis {
  const firedRules: { ruleId: string; points: number; reason: string }[] = [];

  // 1. Extract UTR / Transaction ID
  const utrMatch = text.match(/\b(?:utr|txn\s*(?:id|no)?|ref(?:\s*no)?|rrn)\s*[:#\-]?\s*([a-zA-Z0-9\-_]{4,24})/i);
  let utrNumber: string | undefined;
  let isUtrValid = false;
  let missingReference = false;
  let formatMismatch = false;

  if (utrMatch) {
    utrNumber = utrMatch[1];
    isUtrValid = validateUpiUtr(utrNumber);
    if (!isUtrValid) {
      formatMismatch = true;
      firedRules.push({
        ruleId: 'RECEIPT_FORMAT_MISMATCH',
        points: 20,
        reason: `Transaction reference "${utrNumber}" does not follow standard 12-digit Indian banking format.`,
      });
    }
  } else {
    missingReference = true;
    firedRules.push({
      ruleId: 'RECEIPT_MISSING_REFERENCE',
      points: 15,
      reason: 'Payment screenshot or text is missing mandatory 12-digit bank UTR reference number.',
    });
  }

  // 2. Check Amount in digits vs Amount in words mismatch
  let amountMismatch = false;
  const digitMatch = text.match(/(?:rs\.?|inr|₹)\s*(\d+(?:,\d+)*(?:\.\d+)?)/i);
  if (digitMatch) {
    const numericVal = parseInt(digitMatch[1].replace(/,/g, ''), 10);
    // Check if conflicting words appear (e.g. text says "ten thousand" but digits say 500)
    if (numericVal < 1000 && /\b(?:thousand|lakh)\b/i.test(text)) {
      amountMismatch = true;
      firedRules.push({
        ruleId: 'RECEIPT_AMOUNT_MISMATCH',
        points: 20,
        reason: 'Numerical transaction amount conflicts with words stated in payment description.',
      });
    }
  }

  // 3. Pressure after receipt
  let pressureDetected = false;
  if (/\b(?:paid\s+(?:already|now)|transferred\s+now|send\s+(?:goods|item|product|parcel)\s+immediately|dispatch\s+now)\b/i.test(text)) {
    pressureDetected = true;
    firedRules.push({
      ruleId: 'PRESSURE_AFTER_RECEIPT',
      points: 20,
      reason: 'Sender demands immediate dispatch of goods right after sharing receipt without verification.',
    });
  }

  return {
    utrNumber,
    isUtrValid,
    amountMismatch,
    missingReference,
    formatMismatch,
    pressureDetected,
    inconclusiveNotice: 'Receipt forensics is advisory. Always confirm actual fund settlement in your official bank statement.',
    firedRules,
  };
}
