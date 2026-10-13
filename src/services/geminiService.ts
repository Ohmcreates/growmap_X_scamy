/**
 * Scam Spotter / Scamy — Google Gemini Cybersecurity Advisory Service
 *
 * Exclusively configured for 4 specific purposes:
 *  1. Message Checker (SMS & Social Engineering Fraud Analysis)
 *  2. URL & Embedded Link Checker (Domain Spoofing & Phishing Detection)
 *  3. Photo OCR Checker (Multimodal Screenshot & Image Text Extraction)
 *  4. AI Nude & Deepfake Detection (Intimate Imagery Forensics & Synthetic Manipulation)
 */

export interface GeminiFraudAnalysis {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'SCAM';
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence_score: number;
  targeted_brand_or_entity: string;
  scam_category:
    | 'Phishing'
    | 'Financial Fraud'
    | 'Lottery/Job Scam'
    | 'Malware Distribution'
    | 'Legitimate/None';
  risk_indicators: string[];
  user_guidance: string;
  sourceModel?: string;
  isAiPowered: boolean;
}

export interface GeminiOcrResult {
  extractedText: string;
  confidence: number;
  documentType: string;
  detectedUrls: string[];
  detectedPhoneNumbers: string[];
  initialFraudAssessment?: {
    isSuspicious: boolean;
    reason: string;
  };
}

export interface GeminiNciiForensicResult {
  isExplicitDetected: boolean;
  explicitClassification: 'NON_EXPLICIT' | 'SUGGESTIVE' | 'EXPLICIT_INTIMATE';
  isAiGenerated: boolean | 'INCONCLUSIVE';
  aiConfidenceScore: number;
  aiArtifacts: string[];
  isManipulated: boolean | 'INCONCLUSIVE';
  manipulationScore: number;
  manipulationTechniques: string[];
  tripartiteVerdict: string;
  safetyAdvice: string;
}

const GEMINI_API_KEY = 'AQ.Ab8RN6LcNqN2lmr8bmd1YLQ0eXb4hmHX8xI-yrHmVH8VHG68Qw';
const PRIMARY_MODEL = 'gemini-3.5-flash';
const FALLBACK_MODELS = ['gemini-3.8-flash'];

export class GeminiService {
  private static apiKey = GEMINI_API_KEY;

  /**
   * Helper to execute Gemini generateContent with automatic model fallback.
   */
  private static async callGeminiApi(
    payload: any,
    targetModel: string = PRIMARY_MODEL
  ): Promise<any> {
    const candidateModels = [targetModel, ...FALLBACK_MODELS.filter((m) => m !== targetModel)];
    let lastError: any = null;

    for (const model of candidateModels) {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${this.apiKey}`;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2500);

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        clearTimeout(timer);

        if (response.ok) {
          const data = await response.json();
          return { data, modelUsed: model };
        } else {
          const errText = await response.text();
          console.warn(`[GeminiService] Model ${model} returned status ${response.status}:`, errText);
          lastError = new Error(`HTTP ${response.status}: ${errText}`);
        }
      } catch (err) {
        console.warn(`[GeminiService] Network failure calling ${model}:`, err);
        lastError = err;
      }
    }

    throw lastError || new Error('All Gemini candidate models failed.');
  }

  // =========================================================================
  // PURPOSE 1 & 2: MESSAGE CHECKER & URL VERIFICATION ENGINE
  // =========================================================================
  /**
   * Analyzes an incoming text message or embedded URL for fraud and social engineering.
   * Employs the user's exact cybersecurity analyst checklist and JSON response schema.
   */
  static async analyzeMessageOrUrl(inputMessageOrUrl: string): Promise<GeminiFraudAnalysis> {
    const trimmed = (inputMessageOrUrl || '').trim();
    if (!trimmed) {
      return {
        verdict: 'SAFE',
        threat_level: 'LOW',
        confidence_score: 100,
        targeted_brand_or_entity: 'None',
        scam_category: 'Legitimate/None',
        risk_indicators: [],
        user_guidance: 'No message provided to analyze.',
        isAiPowered: false,
      };
    }

    const prompt = `You are an expert cybersecurity analyst and fraud detection engine. 

Analyze the following incoming text message and any embedded URLs for fraud, phishing, social engineering, or scam indicators.

--- INPUT MESSAGE ---
${trimmed}
--- END INPUT ---

### Analysis Checklist:
1. Social Engineering Tactics:
   - False urgency or panic (e.g., "Account suspended within 2 hours", "Immediate arrest/legal action").
   - Unrealistic rewards (e.g., lottery winnings, free gift cards, crypto giveaways).
   - Impersonation of trusted authorities, couriers, or banks (e.g., India Post, SBI, PayPal, Amazon, Netflix).

2. URL & Domain Deception:
   - Brand typosquatting, subdomains hiding the actual host, or non-matching domain names.
   - High-risk or unusual TLDs (.xyz, .top, .buzz, .online) used for corporate/banking claims.
   - Use of direct IP addresses or URL masking techniques.

3. Harm Potential:
   - Direct credential harvesting (requests for passwords, PINs, OTPs, seed phrases).
   - APK or malicious file download encouragement.
   - Demands for direct UPI, wire, or cryptocurrency transfers.

### Output Instructions:
Respond ONLY with a valid JSON object matching the schema below. Do not wrap in markdown or add conversational intro/outro text.

{
  "verdict": "SAFE" | "SUSPICIOUS" | "SCAM",
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidence_score": 0-100,
  "targeted_brand_or_entity": "Name of brand spoofed or 'None'",
  "scam_category": "Phishing" | "Financial Fraud" | "Lottery/Job Scam" | "Malware Distribution" | "Legitimate/None",
  "risk_indicators": [
    "List specific red flags found in the message or domain"
  ],
  "user_guidance": "A 1-sentence safe recommendation for the recipient (e.g., 'Do not click the link; check your account directly via the official mobile app.')"
}`;

    const payload = {
      contents: [
        {
          parts: [{ text: prompt }],
        },
      ],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    };

    try {
      const { data, modelUsed } = await this.callGeminiApi(payload);
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) throw new Error('No candidate content received from Gemini.');

      const parsed: GeminiFraudAnalysis = JSON.parse(rawText);
      parsed.sourceModel = modelUsed;
      parsed.isAiPowered = true;
      return parsed;
    } catch (err) {
      console.warn('[GeminiService] Falling back to local heuristic analysis:', err);
      return this.fallbackLocalAnalysis(trimmed);
    }
  }

  // =========================================================================
  // PURPOSE 3: PHOTO OCR CHECKER (Screenshots, Receipts & Visual Messages)
  // =========================================================================
  /**
   * Performs optical text extraction and visual fraud assessment on uploaded photos/screenshots.
   */
  static async performPhotoOcr(base64Data: string, mimeType: string = 'image/jpeg'): Promise<GeminiOcrResult> {
    const cleanBase64 = base64Data.replace(/^data:[^;]+;base64,/, '');

    const prompt = `You are a specialized optical character recognition (OCR) and document forensics engine.

Carefully inspect the provided image (screenshot of a text message, WhatsApp chat, payment receipt, or letter):
1. Extract ALL readable text verbatim without omission or alteration.
2. Identify the document type (e.g., "SMS Screenshot", "Payment Receipt", "WhatsApp Conversation", "Notice").
3. Detect any URLs, links, or domain names present in the text.
4. Detect any phone numbers or UPI VPAs present in the text.
5. Provide a brief assessment of whether the document shows visible fraud, forged stamps, or coercion.

Respond ONLY with a valid JSON object matching this schema:
{
  "extractedText": "Full verbatim text extracted from the image",
  "confidence": 0-100,
  "documentType": "Document type label",
  "detectedUrls": ["List of detected URLs"],
  "detectedPhoneNumbers": ["List of detected phone numbers"],
  "initialFraudAssessment": {
    "isSuspicious": boolean,
    "reason": "1-sentence summary of suspicion or legitimacy"
  }
}`;

    const payload = {
      contents: [
        {
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType,
                data: cleanBase64,
              },
            },
          ],
        },
      ],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    };

    try {
      const { data } = await this.callGeminiApi(payload);
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) throw new Error('No OCR text extracted by Gemini.');

      const parsed: GeminiOcrResult = JSON.parse(rawText);
      return parsed;
    } catch (err) {
      console.warn('[GeminiService] Gemini Photo OCR failed:', err);
      throw err;
    }
  }

  // =========================================================================
  // PURPOSE 4: AI NUDE & DEEPFAKE INTIMATE IMAGE FORENSICS (NCII SHIELD)
  // =========================================================================
  /**
   * Conducts tripartite intimate image forensics:
   * 1. Content Safety Screening (nudity/explicit presence)
   * 2. AI-Generation Forensics (synthetic diffusion markers)
   * 3. Manipulation / Deepfake Forensics (face swaps, boundary seam tampering)
   */
  static async analyzeIntimateImageForensics(
    base64Data: string,
    mimeType: string = 'image/jpeg'
  ): Promise<GeminiNciiForensicResult> {
    const cleanBase64 = base64Data.replace(/^data:[^;]+;base64,/, '');

    const prompt = `You are a forensic image authenticity and Non-Consensual Intimate Imagery (NCII) analyst.

Examine the uploaded image across three distinct forensic dimensions:
1. Explicit & Intimate Content Screening:
   - Does this image contain nudity, intimate exposure, or sexually explicit content?
   - Classify as: "NON_EXPLICIT", "SUGGESTIVE", or "EXPLICIT_INTIMATE".

2. AI Generation Forensics:
   - Does the image exhibit characteristics of generative AI diffusion models (e.g., Midjourney, Stable Diffusion, Flux, DALL-E)?
   - Look for: unnatural skin texture smoothing, irregular hair fiber cohesion, distorted finger/hand anatomy, pupil asymmetry, synthetic lighting contradictions.
   - Return isAiGenerated as true, false, or "INCONCLUSIVE". Provide a confidence score (0-100) and list of observed artifacts.

3. Image Manipulation / Deepfake Face-Swap Analysis:
   - Look for signs of digital compositing, face swaps, boundary seam blurring, noise/compression divergence between face and torso.
   - Return isManipulated as true, false, or "INCONCLUSIVE". Provide manipulation score (0-100) and list of techniques.

Safety Principle: Keep all three assessments distinct. Do not merge AI-generation with consent. Never attempt identity deanonymization.

Respond ONLY with a valid JSON object matching this schema:
{
  "isExplicitDetected": boolean,
  "explicitClassification": "NON_EXPLICIT" | "SUGGESTIVE" | "EXPLICIT_INTIMATE",
  "isAiGenerated": true | false | "INCONCLUSIVE",
  "aiConfidenceScore": 0-100,
  "aiArtifacts": ["List of detected AI generation artifacts"],
  "isManipulated": true | false | "INCONCLUSIVE",
  "manipulationScore": 0-100,
  "manipulationTechniques": ["List of manipulation signals"],
  "tripartiteVerdict": "1-sentence consolidated forensic summary",
  "safetyAdvice": "1-sentence consumer advisory (e.g., reporting guidance to 1930 / StopNCII.org)"
}`;

    const payload = {
      contents: [
        {
          parts: [
            { text: prompt },
            {
              inlineData: {
                mimeType,
                data: cleanBase64,
              },
            },
          ],
        },
      ],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    };

    try {
      const { data } = await this.callGeminiApi(payload);
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) throw new Error('No forensic report received from Gemini.');

      const parsed: GeminiNciiForensicResult = JSON.parse(rawText);
      return parsed;
    } catch (err) {
      console.warn('[GeminiService] Gemini NCII Forensics failed:', err);
      throw err;
    }
  }

  // =========================================================================
  // LOCAL FALLBACK GENERATOR (RESILIENCY SAFETY NET)
  // =========================================================================
  private static fallbackLocalAnalysis(text: string): GeminiFraudAnalysis {
    const lower = text.toLowerCase();
    const hasUrgency = /\b(?:immediately|urgent|within\s+24|action|cut|blocked|arrest|notice)\b/i.test(lower);
    const hasLink = /https?:\/\/|\bwww\.|\.[a-z]{2,}\b/i.test(lower);
    const hasFinancial = /\b(?:rs\.?|inr|otp|cvv|pin|bank|account|challan|payment|kyc)\b/i.test(lower);

    let verdict: GeminiFraudAnalysis['verdict'] = 'SAFE';
    let threatLevel: GeminiFraudAnalysis['threat_level'] = 'LOW';
    let confidence = 75;
    const indicators: string[] = [];

    if (hasUrgency && hasLink && hasFinancial) {
      verdict = 'SCAM';
      threatLevel = 'HIGH';
      confidence = 92;
      indicators.push('Urgent pressure tactic combined with unverified link');
      indicators.push('Demands for financial settlement or credential disclosure');
    } else if (hasUrgency || hasLink) {
      verdict = 'SUSPICIOUS';
      threatLevel = 'MEDIUM';
      confidence = 70;
      indicators.push('Unverified link or unexpected compliance timeline');
    }

    let brand = 'None';
    if (lower.includes('sbi')) brand = 'State Bank of India';
    else if (lower.includes('parivahan') || lower.includes('challan')) brand = 'Parivahan / MoRTH';
    else if (lower.includes('paypal')) brand = 'PayPal';
    else if (lower.includes('amazon')) brand = 'Amazon';
    else if (lower.includes('post')) brand = 'India Post';

    return {
      verdict,
      threat_level: threatLevel,
      confidence_score: confidence,
      targeted_brand_or_entity: brand,
      scam_category: verdict === 'SCAM' ? 'Phishing' : verdict === 'SUSPICIOUS' ? 'Financial Fraud' : 'Legitimate/None',
      risk_indicators: indicators.length > 0 ? indicators : ['Standard format correspondence'],
      user_guidance: verdict === 'SCAM'
        ? 'Do not open any attached links; verify your account status directly through official channels.'
        : 'Verify any unexpected correspondence independently.',
      sourceModel: 'Local Heuristic Failover',
      isAiPowered: false,
    };
  }
}
