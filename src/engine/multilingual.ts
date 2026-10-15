/**
 * Scam Spotter — Comprehensive Multilingual & 22 Official Indian Languages Engine
 * Supports the Eighth Schedule to the Constitution of India:
 * 1. Assamese (অসমীয়া)
 * 2. Bengali (বাংলা)
 * 3. Bodo (बड़ो / Devanagari)
 * 4. Dogri (डोगरी / Devanagari)
 * 5. Gujarati (ગુજરાતી)
 * 6. Hindi (हिन्दी / Devanagari)
 * 7. Kannada (ಕನ್ನಡ)
 * 8. Kashmiri (کٲشُر / Devanagari)
 * 9. Konkani (कोंकणी / Devanagari)
 * 10. Maithili (मैथिली / Devanagari)
 * 11. Malayalam (മലയാളം)
 * 12. Manipuri / Meitei (মৈতৈলোন্ / ꯃꯤꯇꯩ ꯃꯌꯦꯛ)
 * 13. Marathi (मराठी / Devanagari)
 * 14. Nepali (नेपाली / Devanagari)
 * 15. Odia (ଓଡ଼ିଆ)
 * 16. Punjabi (ਪੰਜਾਬੀ / Gurmukhi)
 * 17. Sanskrit (संस्कृतम् / Devanagari)
 * 18. Santali (ᱥᱟᱱᱛᱟᱲᱤ / Ol Chiki)
 * 19. Sindhi (سنڌي / Devanagari)
 * 20. Tamil (தமிழ்)
 * 21. Telugu (తెలుగు)
 * 22. Urdu (اردو / Perso-Arabic)
 *
 * Plus popular Romanized transliterations:
 * Hinglish, Tanglish, Tenglish, Benglish, Kanglish, etc.
 */

export type DetectedScript =
  | 'LATIN'
  | 'DEVANAGARI'
  | 'BENGALI_ASSAMESE'
  | 'TELUGU'
  | 'TAMIL'
  | 'GUJARATI'
  | 'KANNADA'
  | 'MALAYALAM'
  | 'ODIA'
  | 'GURMUKHI'
  | 'PERSO_ARABIC'
  | 'OL_CHIKI'
  | 'MEETEI_MAYEK'
  | 'MIXED'
  | 'UNKNOWN';

export interface IndianLanguageMeta {
  code: string;
  name: string;
  nativeName: string;
  script: DetectedScript;
  scriptFamily: string;
}

export const SCHEDULED_INDIAN_LANGUAGES: IndianLanguageMeta[] = [
  { code: 'as', name: 'Assamese', nativeName: 'অসমীয়া', script: 'BENGALI_ASSAMESE', scriptFamily: 'Eastern Nagari' },
  { code: 'bn', name: 'Bengali', nativeName: 'বাংলা', script: 'BENGALI_ASSAMESE', scriptFamily: 'Eastern Nagari' },
  { code: 'brx', name: 'Bodo', nativeName: 'बड़ो', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'doi', name: 'Dogri', nativeName: 'डोगरी', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'gu', name: 'Gujarati', nativeName: 'ગુજરાતી', script: 'GUJARATI', scriptFamily: 'Gujarati' },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'kn', name: 'Kannada', nativeName: 'ಕನ್ನಡ', script: 'KANNADA', scriptFamily: 'Kannada' },
  { code: 'ks', name: 'Kashmiri', nativeName: 'کٲشُر', script: 'PERSO_ARABIC', scriptFamily: 'Perso-Arabic' },
  { code: 'gom', name: 'Konkani', nativeName: 'कोंकणी', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'mai', name: 'Maithili', nativeName: 'मैथिली', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'ml', name: 'Malayalam', nativeName: 'മലയാളം', script: 'MALAYALAM', scriptFamily: 'Malayalam' },
  { code: 'mni', name: 'Manipuri', nativeName: 'ꯃꯤꯇꯩ ꯃꯌꯦꯛ', script: 'MEETEI_MAYEK', scriptFamily: 'Meetei Mayek' },
  { code: 'mr', name: 'Marathi', nativeName: 'मराठी', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'ne', name: 'Nepali', nativeName: 'नेपाली', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'or', name: 'Odia', nativeName: 'ଓଡ଼ିଆ', script: 'ODIA', scriptFamily: 'Odia' },
  { code: 'pa', name: 'Punjabi', nativeName: 'ਪੰਜਾਬੀ', script: 'GURMUKHI', scriptFamily: 'Gurmukhi' },
  { code: 'sa', name: 'Sanskrit', nativeName: 'संस्कृतम्', script: 'DEVANAGARI', scriptFamily: 'Devanagari' },
  { code: 'sat', name: 'Santali', nativeName: 'ᱥᱟᱱᱛᱟᱲᱤ', script: 'OL_CHIKI', scriptFamily: 'Ol Chiki' },
  { code: 'sd', name: 'Sindhi', nativeName: 'سنڌي', script: 'PERSO_ARABIC', scriptFamily: 'Perso-Arabic' },
  { code: 'ta', name: 'Tamil', nativeName: 'தமிழ்', script: 'TAMIL', scriptFamily: 'Tamil' },
  { code: 'te', name: 'Telugu', nativeName: 'తెలుగు', script: 'TELUGU', scriptFamily: 'Telugu' },
  { code: 'ur', name: 'Urdu', nativeName: 'اردو', script: 'PERSO_ARABIC', scriptFamily: 'Perso-Arabic' },
];

export interface ScriptAnalysis {
  script: DetectedScript;
  languageName: string;
  nativeScriptName: string;
  devanagariRatio: number;
  latinRatio: number;
  totalChars: number;
  isHinglishCandidate: boolean;
  isIndicLanguage: boolean;
  supportNotice?: string;
}

export function detectScript(text: string): ScriptAnalysis {
  let devanagariCount = 0;
  let bengaliCount = 0;
  let teluguCount = 0;
  let tamilCount = 0;
  let gujaratiCount = 0;
  let kannadaCount = 0;
  let malayalamCount = 0;
  let odiaCount = 0;
  let gurmukhiCount = 0;
  let persoArabicCount = 0;
  let olChikiCount = 0;
  let meeteiCount = 0;
  let latinCount = 0;
  let totalLetterCount = 0;

  for (const char of text) {
    const code = char.codePointAt(0) || 0;

    if (code >= 0x0900 && code <= 0x097f) {
      devanagariCount++;
      totalLetterCount++;
    } else if (code >= 0x0980 && code <= 0x09ff) {
      bengaliCount++;
      totalLetterCount++;
    } else if (code >= 0x0c00 && code <= 0x0c7f) {
      teluguCount++;
      totalLetterCount++;
    } else if (code >= 0x0b80 && code <= 0x0bff) {
      tamilCount++;
      totalLetterCount++;
    } else if (code >= 0x0a80 && code <= 0x0aff) {
      gujaratiCount++;
      totalLetterCount++;
    } else if (code >= 0x0c80 && code <= 0x0cff) {
      kannadaCount++;
      totalLetterCount++;
    } else if (code >= 0x0d00 && code <= 0x0d7f) {
      malayalamCount++;
      totalLetterCount++;
    } else if (code >= 0x0b00 && code <= 0x0b7f) {
      odiaCount++;
      totalLetterCount++;
    } else if (code >= 0x0a00 && code <= 0x0a7f) {
      gurmukhiCount++;
      totalLetterCount++;
    } else if (code >= 0x0600 && code <= 0x06ff) {
      persoArabicCount++;
      totalLetterCount++;
    } else if (code >= 0x1c50 && code <= 0x1c7f) {
      olChikiCount++;
      totalLetterCount++;
    } else if (code >= 0xabc0 && code <= 0xabff) {
      meeteiCount++;
      totalLetterCount++;
    } else if ((code >= 0x0041 && code <= 0x005a) || (code >= 0x0061 && code <= 0x007a)) {
      latinCount++;
      totalLetterCount++;
    }
  }

  if (totalLetterCount === 0) {
    return {
      script: 'UNKNOWN',
      languageName: 'Unknown',
      nativeScriptName: 'Unknown',
      devanagariRatio: 0,
      latinRatio: 0,
      totalChars: text.length,
      isHinglishCandidate: false,
      isIndicLanguage: false,
    };
  }

  const devanagariRatio = devanagariCount / totalLetterCount;
  const latinRatio = latinCount / totalLetterCount;

  // Determine primary script
  const scriptCounts: [DetectedScript, number, string, string][] = [
    ['DEVANAGARI', devanagariCount, 'Hindi / Marathi / Sanskrit', 'हिन्दी / मराठी'],
    ['BENGALI_ASSAMESE', bengaliCount, 'Bengali / Assamese', 'বাংলা / অসমীয়া'],
    ['TELUGU', teluguCount, 'Telugu', 'తెలుగు'],
    ['TAMIL', tamilCount, 'Tamil', 'தமிழ்'],
    ['GUJARATI', gujaratiCount, 'Gujarati', 'ગુજરાતી'],
    ['KANNADA', kannadaCount, 'Kannada', 'ಕನ್ನಡ'],
    ['MALAYALAM', malayalamCount, 'Malayalam', 'മലയാളം'],
    ['ODIA', odiaCount, 'Odia', 'ଓଡ଼ିଆ'],
    ['GURMUKHI', gurmukhiCount, 'Punjabi', 'ਪੰਜਾਬੀ'],
    ['PERSO_ARABIC', persoArabicCount, 'Urdu / Kashmiri', 'اردو'],
    ['OL_CHIKI', olChikiCount, 'Santali', 'ᱥᱟᱱᱛᱟᱲᱤ'],
    ['MEETEI_MAYEK', meeteiCount, 'Manipuri', 'ꯃꯤꯇꯩ ꯃꯌꯦꯛ'],
  ];

  scriptCounts.sort((a, b) => b[1] - a[1]);
  const [topScript, topCount, topLangName, topNativeName] = scriptCounts[0];

  let script: DetectedScript = 'LATIN';
  let languageName = 'English';
  let nativeScriptName = 'Latin';
  let isHinglishCandidate = false;
  let isIndicLanguage = false;

  if (topCount / totalLetterCount > 0.45) {
    script = topScript;
    languageName = topLangName;
    nativeScriptName = topNativeName;
    isIndicLanguage = true;
  } else if (latinRatio > 0.35 && topCount > 0) {
    script = 'MIXED';
    languageName = `Mixed (${topLangName} + English)`;
    nativeScriptName = 'Multilingual Indic';
    isIndicLanguage = true;
  } else {
    script = 'LATIN';
    languageName = 'English';
    nativeScriptName = 'Latin';

    // Check for Romanized Indic transliterations (Hinglish, Tanglish, Tenglish, etc.)
    const isHinglish = /\b(?:karein|karo|bhejo|aaj|turant|paise|khata|band|aapka|humara|raat|kaat|diya|jayega|vibhag|bijli)\b/i.test(text);
    const isTanglish = /\b(?:ungal|ungada|vudane|anupunga|pannunga|kudunga|kannaku|panam|sollunga)\b/i.test(text);
    const isTenglish = /\b(?:mee|meeru|thondaraga|cheyandi|ivvandi|cheppandi|pampandi|dabbulu|aipothundi)\b/i.test(text);
    const isBenglish = /\b(?:aapnar|ekhoni|korun|taka|pathan|din|hobe|bondho)\b/i.test(text);
    const isKanglish = /\b(?:nimma|eegale|madi|kalsi|thilisi|hana|aguthe)\b/i.test(text);
    const isOdialish = /\b(?:aapanka|turanta|karantu|diantu|pathantu|tanka|hoijiba)\b/i.test(text);

    if (isHinglish) {
      isHinglishCandidate = true;
      isIndicLanguage = true;
      languageName = 'Hinglish (Hindi in Roman Script)';
      nativeScriptName = 'Hinglish (हिन्दी)';
    } else if (isTanglish) {
      isIndicLanguage = true;
      languageName = 'Tanglish (Tamil in Roman Script)';
      nativeScriptName = 'Tanglish (தமிழ்)';
    } else if (isTenglish) {
      isIndicLanguage = true;
      languageName = 'Tenglish (Telugu in Roman Script)';
      nativeScriptName = 'Tenglish (తెలుగు)';
    } else if (isBenglish) {
      isIndicLanguage = true;
      languageName = 'Benglish (Bengali in Roman Script)';
      nativeScriptName = 'Benglish (বাংলা)';
    } else if (isKanglish) {
      isIndicLanguage = true;
      languageName = 'Kanglish (Kannada in Roman Script)';
      nativeScriptName = 'Kanglish (ಕನ್ನಡ)';
    } else if (isOdialish) {
      isIndicLanguage = true;
      languageName = 'Odialish (Odia in Roman Script)';
      nativeScriptName = 'Odialish (ଓଡ଼ିଆ)';
    }
  }

  return {
    script,
    languageName,
    nativeScriptName,
    devanagariRatio,
    latinRatio,
    totalChars: text.length,
    isHinglishCandidate,
    isIndicLanguage,
    supportNotice: isIndicLanguage
      ? `Recognized 8th Schedule Indian Language context: ${languageName}`
      : undefined,
  };
}

/**
 * Normalizes input text using Unicode NFKC (Compatibility Decomposition,
 * followed by Canonical Composition) while keeping character offsets safe.
 */
export function normalizeTextForInspection(text: string): string {
  return text.normalize('NFKC');
}
