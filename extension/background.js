// Scam Spotter — Background Service Worker (Manifest V3)

const KNOWN_SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.live', '.club', '.rest'];
const BANK_BRANDS = ['sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe'];

chrome.runtime.onInstalled.addListener(() => {
  console.log('Scam Spotter Extension Shield initialized.');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    const url = request.url.toLowerCase();
    let isSuspicious = false;
    let reason = '';

    // Check suspicious TLDs
    for (const tld of KNOWN_SUSPICIOUS_TLDS) {
      if (url.includes(tld)) {
        isSuspicious = true;
        reason = `Suspicious TLD (${tld}) frequently used in phishing campaigns.`;
        break;
      }
    }

    // Check brand in unofficial domain
    if (!isSuspicious) {
      for (const brand of BANK_BRANDS) {
        if (url.includes(brand) && (url.includes('-kyc') || url.includes('-update') || url.includes('-login'))) {
          isSuspicious = true;
          reason = `Brand "${brand.toUpperCase()}" combined with login/KYC in unofficial domain.`;
          break;
        }
      }
    }

    sendResponse({
      isSuspicious,
      reason,
      floorRuleApplied: isSuspicious,
      score: isSuspicious ? 60 : 0,
    });
  }
  return true;
});
