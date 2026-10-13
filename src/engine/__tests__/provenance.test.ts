import { describe, it, expect } from 'vitest';
import {
  GROWMAP_ZERO_WIDTH_WATERMARK,
  GROWMAP_SIGNATURE_SHA256,
  decodeZeroWidthTrademark,
  verifyGrowmapTrademark,
} from '../provenance.js';

describe('Scamy — Covert Trademark & Provenance Engine', () => {
  it('correctly decodes the invisible zero-width watermark to "growmap"', () => {
    const decoded = decodeZeroWidthTrademark(GROWMAP_ZERO_WIDTH_WATERMARK);
    expect(decoded).toBe('growmap');
  });

  it('watermark has 0 visible rendered footprint (56 zero-width characters)', () => {
    expect(GROWMAP_ZERO_WIDTH_WATERMARK.length).toBe(56);
    // Ensure all characters are strictly zero-width
    for (const ch of GROWMAP_ZERO_WIDTH_WATERMARK) {
      expect(['\u200B', '\u200C']).toContain(ch);
    }
  });

  it('successfully extracts hidden trademark embedded within normal text', () => {
    const maskedText = `Scamy — Check if it's a scam.${GROWMAP_ZERO_WIDTH_WATERMARK} Protect privacy.`;
    const result = verifyGrowmapTrademark(maskedText);
    expect(result.verified).toBe(true);
    expect(result.trademark).toBe('growmap');
    expect(result.sha256).toBe(GROWMAP_SIGNATURE_SHA256);
  });

  it('fails gracefully on arbitrary text without hidden trademark', () => {
    const normalText = 'This is an arbitrary untagged message string.';
    const result = verifyGrowmapTrademark(normalText);
    expect(result.verified).toBe(false);
    expect(result.trademark).toBe('unverified');
  });
});
