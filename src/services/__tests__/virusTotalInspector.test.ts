import { describe, expect, it } from 'vitest';
import {
  calculateShannonEntropy,
  computeMd5,
  createVirusTotalDemoBuffer,
  identifyFileType,
  inspectFileVirusTotal,
  KNOWN_THREAT_HASHES,
  SECURITY_VENDORS,
} from '../virusTotalInspector.js';

describe('Scam Spotter — VirusTotal Multi-Engine File & Hash Inspector', () => {
  it('correctly calculates MD5 checksum and Shannon Entropy', () => {
    const textBytes = new TextEncoder().encode('The quick brown fox jumps over the lazy dog');
    const md5Hash = computeMd5(textBytes);
    expect(md5Hash).toBe('9e107d9d372bb6826bd81d3542a419d6');

    // Uniform/repetitive string has low entropy
    const lowEntropy = calculateShannonEntropy(new Uint8Array([65, 65, 65, 65, 65]));
    expect(lowEntropy).toBe(0);

    // High entropy data
    const randomBlock = new Uint8Array(256);
    for (let i = 0; i < 256; i++) randomBlock[i] = i;
    const highEntropy = calculateShannonEntropy(randomBlock);
    expect(highEntropy).toBe(8);
  });

  it('accurately identifies file magic headers for PE, ZIP, PDF, and Scripts', () => {
    const peBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    expect(identifyFileType(peBytes, 'malware.exe').fileType).toContain('PE Executable');

    const zipBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04]);
    expect(identifyFileType(zipBytes, 'trojan.apk').fileType).toContain('Android Package');

    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    expect(identifyFileType(pdfBytes, 'doc.pdf').fileType).toContain('PDF');

    const shBytes = new Uint8Array([0x23, 0x21, 0x2f, 0x62]);
    expect(identifyFileType(shBytes, 'run.sh').fileType).toContain('POSIX Script');
  });

  it('detects high-risk ransomware payload with high detection ratio (50+/72 vendors)', async () => {
    const { buffer, fileName } = createVirusTotalDemoBuffer('RANSOMWARE_PAYLOAD');
    const report = await inspectFileVirusTotal(buffer, fileName);

    expect(report.verdict).toBe('MALICIOUS');
    expect(report.riskLevel).toBe('HIGH');
    expect(report.stats.malicious).toBeGreaterThanOrEqual(50);
    expect(report.stats.totalEngines).toBe(SECURITY_VENDORS.length);
    expect(report.stats.detectionRatio).toContain(`/ ${SECURITY_VENDORS.length}`);
    expect(report.hashes.md5).toHaveLength(32);
    expect(report.extractedStrings.apis).toContain('Process Injection (CreateRemoteThread)');
    expect(report.behaviorSignals.length).toBeGreaterThan(0);
    expect(report.recommendations[0]).toContain('DO NOT execute');
  });

  it('flags suspicious dropper script with moderate detection ratio', async () => {
    const { buffer, fileName } = createVirusTotalDemoBuffer('SUSPICIOUS_DROPPER');
    const report = await inspectFileVirusTotal(buffer, fileName);

    expect(['SUSPICIOUS', 'MALICIOUS']).toContain(report.verdict);
    expect(report.stats.malicious).toBeGreaterThan(0);
    expect(report.extractedStrings.urls.length).toBeGreaterThan(0);
    expect(report.extractedStrings.ips.length).toBeGreaterThan(0);
  });

  it('verifies clean utility report with 0/72 vendor detections', async () => {
    const { buffer, fileName } = createVirusTotalDemoBuffer('CLEAN_TOOL');
    const report = await inspectFileVirusTotal(buffer, fileName);

    expect(report.verdict).toBe('CLEAN');
    expect(report.stats.malicious).toBe(0);
    expect(report.stats.detectionRatio).toBe(`0 / ${SECURITY_VENDORS.length}`);
    expect(report.reputationScore).toBeGreaterThan(0);
    expect(report.recommendations[0]).toContain('Clean verdict');
  });

  it('identifies known malware hash (WannaCry, EICAR) from built-in threat database', () => {
    const wannacrySha256 = '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c';
    expect(KNOWN_THREAT_HASHES[wannacrySha256]).toBeDefined();
    expect(KNOWN_THREAT_HASHES[wannacrySha256].classification).toContain('WannaCrypt');
    expect(KNOWN_THREAT_HASHES[wannacrySha256].maliciousVendors).toBe(71);
  });
});
