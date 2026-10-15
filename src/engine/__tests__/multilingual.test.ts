import { describe, expect, it } from 'vitest';
import { detectScript, normalizeTextForInspection } from '../multilingual.js';
import { analyzeMessage } from '../scorer.js';

describe('Scam Spotter — Phase 4 Multilingual & Hinglish NLP Engine', () => {
  it('correctly detects Devanagari script ratio', () => {
    const hindiText = 'आपका खाता बंद कर दिया जाएगा';
    const analysis = detectScript(hindiText);

    expect(analysis.script).toBe('DEVANAGARI');
    expect(analysis.devanagariRatio).toBeGreaterThan(0.8);
  });

  it('detects Hinglish candidate phrasing in Latin script', () => {
    const hinglish = 'Aapka account band ho jayega turant paise wapas karo';
    const analysis = detectScript(hinglish);

    expect(analysis.script).toBe('LATIN');
    expect(analysis.isHinglishCandidate).toBe(true);
  });

  it('normalizes NFKC unicode lookalikes correctly', () => {
    // Full-width latin characters
    const fullWidth = 'ＯＴＰ';
    const normalized = normalizeTextForInspection(fullWidth);
    expect(normalized).toBe('OTP');
  });

  it('scores Hinglish scam with exact parity to English counterparts', () => {
    const hinglishScam = 'Aapka account band ho jayega. Turant OTP share karein.';
    const result = analyzeMessage(hinglishScam);

    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.riskLevel).toBe('HIGH');

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('OTP_REQUEST');
  });

  it('fires rules for pure Devanagari Hindi scam message', () => {
    const hindiScam = 'आपका खाता बंद कर दिया जाएगा तुरंत ओटीपी भेजें';
    const result = analyzeMessage(hindiScam);

    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('OTP_REQUEST');
    expect(result.riskLevel).toBe('HIGH');
  });

  it('detects Bengali script and scores regional electricity scam as HIGH RISK', () => {
    const bengaliScam = 'প্রিয় গ্রাহক, আপনার বিদ্যুৎ বিল বকেয়া রয়েছে। আজ রাতে বিদ্যুৎ সংযোগ বিচ্ছিন্ন করা হবে। অবিলম্বে বিদ্যুৎ দপ্তর 9876543210 নম্বরে যোগাযোগ করুন।';
    const analysis = detectScript(bengaliScam);
    expect(analysis.script).toBe('BENGALI_ASSAMESE');
    expect(analysis.isIndicLanguage).toBe(true);

    const result = analyzeMessage(bengaliScam);
    expect(result.riskLevel).toBe('HIGH');
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('AUTHORITY_IMPERSONATION');
  });

  it('detects Tamil script and scores regional electricity scam as HIGH RISK', () => {
    const tamilScam = 'அன்புள்ள வாடிக்கையாளரே, உங்கள் மின்சார கட்டணம் நிலுவையில் உள்ளது. இன்றிரவு மின் இணைப்பு துண்டிக்கப்படும். உடனடியாக மின்சார வாரியத்தை 9876543210 அழைக்கவும்.';
    const analysis = detectScript(tamilScam);
    expect(analysis.script).toBe('TAMIL');
    expect(analysis.isIndicLanguage).toBe(true);

    const result = analyzeMessage(tamilScam);
    expect(result.riskLevel).toBe('HIGH');
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('AUTHORITY_IMPERSONATION');
  });

  it('detects Telugu script and scores regional electricity scam as HIGH RISK', () => {
    const teluguScam = 'ప్రియమైన వినియోగదారు, మీ విద్యుత్ బిల్లు బకాయి ఉంది. ఈ రాత్రి కరెంట్ కట్ అవుతుంది. వెంటనే విద్యుత్ అధికారిని 9876543210 నంబర్‌లో సంప్రదించండి.';
    const analysis = detectScript(teluguScam);
    expect(analysis.script).toBe('TELUGU');
    expect(analysis.isIndicLanguage).toBe(true);

    const result = analyzeMessage(teluguScam);
    expect(result.riskLevel).toBe('HIGH');
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('AUTHORITY_IMPERSONATION');
  });

  it('detects Odia script and scores regional electricity scam as HIGH RISK', () => {
    const odiaScam = 'ପ୍ରିୟ ଗ୍ରାହକ, ଆପଣଙ୍କ ବିଦ୍ୟୁତ ବିଲ ବକେୟା ଅଛି। ଆଜି ରାତିରେ ବିଦ୍ୟୁତ ସଂଯୋଗ ବିଚ୍ଛିନ୍ନ ହେବ। ତୁରନ୍ତ ବିଦ୍ୟୁତ ଅଧିକାରୀଙ୍କୁ 9876543210 ରେ କଲ କରନ୍ତୁ।';
    const analysis = detectScript(odiaScam);
    expect(analysis.script).toBe('ODIA');
    expect(analysis.isIndicLanguage).toBe(true);

    const result = analyzeMessage(odiaScam);
    expect(result.riskLevel).toBe('HIGH');
    const firedIds = result.breakdown.map((b) => b.ruleId);
    expect(firedIds).toContain('ACCOUNT_THREAT');
    expect(firedIds).toContain('URGENCY');
    expect(firedIds).toContain('AUTHORITY_IMPERSONATION');
  });

  it('detects Gujarati, Gurmukhi, Kannada, Malayalam, and Perso-Arabic scripts', () => {
    expect(detectScript('તમારું ખાતું બ્લોક થઈ ગયું છે').script).toBe('GUJARATI');
    expect(detectScript('ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ ਹੋ ਗਿਆ ਹੈ').script).toBe('GURMUKHI');
    expect(detectScript('ನಿಮ್ಮ ಖಾತೆಯನ್ನು ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ').script).toBe('KANNADA');
    expect(detectScript('നിങ്ങളുടെ അക്കൗണ്ട് ബ്ലോക്ക് ചെയ്തു').script).toBe('MALAYALAM');
    expect(detectScript('آپ کا اکاؤنٹ بلاک کر دیا گیا ہے').script).toBe('PERSO_ARABIC');
  });
});
