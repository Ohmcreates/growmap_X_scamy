import { describe, it, expect } from 'vitest';
import { NciiDetector, ImageSampleInput } from '../nciiDetector';

describe('Scamy — AI-Generated Nude & NCII Deepfake Forensics Engine', () => {
  it('maintains strict tripartite separation across nudity, AI-generation, and manipulation', async () => {
    // A synthetic deepfake nude sample
    const sample: ImageSampleInput = {
      name: 'suspicious_leak.jpg',
      size: 420000,
      type: 'image/jpeg',
      mockCategory: 'DEEPFAKE_FACE_SWAP',
    };

    const report = await NciiDetector.analyzeImage(sample);

    // 1. Explicit Content Screening
    expect(report.explicitScreening.isExplicitDetected).toBe(true);
    expect(report.explicitScreening.privacyRouting).toBe('SHIELD_BLUR_APPLIED');
    expect(report.explicitScreening.exposureScore).toBeGreaterThan(50);

    // 2. AI-Generation Assessment: Face-swap is a localized splice, so full-frame AI is Inconclusive
    expect(report.aiGeneration.calibratedVerdict).toBe('INCONCLUSIVE');

    // 3. Manipulation Assessment: Face-swap is flagged with high score
    expect(report.manipulation.isManipulated).toBe(true);
    expect(report.manipulation.manipulationVerdict).toBe('SUSPECTED_DEEPFAKE_SWAP');
    expect(report.manipulation.faceSwapIndicators.boundaryBlendingArtifacts).toBe(true);
    expect(report.manipulation.errorLevelAnalysis.suspiciousResavedRegions).toBe(true);
  });

  it('correctly identifies full-frame AI Diffusion synthetic nude generation', async () => {
    const sample: ImageSampleInput = {
      name: 'sdxl_generated_portrait.png',
      size: 1540000,
      type: 'image/png',
      mockCategory: 'AI_DIFFUSION_NUDE',
    };

    const report = await NciiDetector.analyzeImage(sample);

    expect(report.explicitScreening.isExplicitDetected).toBe(true);
    expect(report.aiGeneration.isAiGenerated).toBe(true);
    expect(report.aiGeneration.calibratedVerdict).toBe('HIGH_PROBABILITY_AI');
    expect(report.aiGeneration.aiConfidenceScore).toBeGreaterThanOrEqual(90);
    expect(report.aiGeneration.generatorSignaturesDetected.length).toBeGreaterThan(0);

    // Full-frame generation is NOT a face swap splice
    expect(report.manipulation.manipulationVerdict).toBe('UNLIKELY_MANIPULATED');
  });

  it('verifies consented real camera photographs as non-AI and non-manipulated', async () => {
    const sample: ImageSampleInput = {
      name: 'vacation_family_photo.jpg',
      size: 2800000,
      type: 'image/jpeg',
      mockCategory: 'CONSENTED_REAL_PHOTO',
    };

    const report = await NciiDetector.analyzeImage(sample);

    expect(report.explicitScreening.isExplicitDetected).toBe(false);
    expect(report.explicitScreening.privacyRouting).toBe('SAFE_NON_EXPLICIT');
    expect(report.aiGeneration.isAiGenerated).toBe(false);
    expect(report.aiGeneration.calibratedVerdict).toBe('PROBABLE_REAL_CAMERA');
    expect(report.manipulation.isManipulated).toBe(false);
    expect(report.manipulation.manipulationVerdict).toBe('UNLIKELY_MANIPULATED');
  });

  it('safely outputs an INCONCLUSIVE outcome when image is heavily compressed or degraded', async () => {
    const sample: ImageSampleInput = {
      name: 'whatsapp_recompressed_artifact.jpg',
      size: 45000,
      type: 'image/jpeg',
      mockCategory: 'COMPRESSED_SUSPICIOUS',
    };

    const report = await NciiDetector.analyzeImage(sample);

    // Must avoid claiming false certainty as specified in section 3 of specs
    expect(report.aiGeneration.isAiGenerated).toBe('INCONCLUSIVE');
    expect(report.aiGeneration.calibratedVerdict).toBe('INCONCLUSIVE');
    expect(report.manipulation.manipulationVerdict).toBe('INCONCLUSIVE');
    expect(report.aiGeneration.limitationsNotice).toContain('Compression degradations prevent definitive');
  });

  it('detects C2PA and embedded AI metadata provenance in image headers', async () => {
    // Create a mock buffer with embedded ComfyUI and C2PA markers
    const textEncoder = new TextEncoder();
    const mockBytes = textEncoder.encode('RIFF....WEBPVP8 ...c2pa...parameters: Steps: 25, Sampler: DPM++ 2M, Model: SDXL');

    const sample: ImageSampleInput = {
      name: 'comfyui_metadata_sample.webp',
      size: mockBytes.length,
      type: 'image/webp',
      buffer: mockBytes,
    };

    const report = await NciiDetector.analyzeImage(sample);

    expect(report.provenance.hasProvenanceCredentials).toBe(true);
    expect(report.provenance.c2paManifestFound).toBe(true);
    expect(report.provenance.pngTextChunks.some((c) => c.keyword === 'parameters')).toBe(true);
    expect(report.aiGeneration.calibratedVerdict).toBe('HIGH_PROBABILITY_AI');
  });

  it('generates actionable NCII victim assistance, StopNCII.org platform links, and evidence protocol', async () => {
    const sample: ImageSampleInput = {
      name: 'extortion_attempt_image.jpg',
      size: 512000,
      type: 'image/jpeg',
      mockCategory: 'AI_DIFFUSION_NUDE',
    };

    const report = await NciiDetector.analyzeImage(sample);

    expect(report.legalProtocol.victimHelplines.some((h) => h.contact.includes('1930'))).toBe(true);
    expect(report.legalProtocol.takeDownPlatforms.some((p) => p.url.includes('stopncii.org'))).toBe(true);
    expect(report.legalProtocol.takeDownPlatforms.some((p) => p.url.includes('takeitdown.ncmec.org'))).toBe(true);
    expect(report.legalProtocol.evidencePreservationSteps.length).toBeGreaterThanOrEqual(3);
    expect(report.privacyNotice).toContain('100% Client-Side Privacy');
  });
});
