import { describe, it, expect } from 'vitest';
import { createDemoSampleApk, inspectApkFile } from '../apkInspector.js';

describe('Scam Spotter — Android APK Security Inspector (Reverse Engineered from SpotTheScam.in)', () => {
  it('detects banking trojan characteristics, critical permissions, and debug signature in malicious APK', async () => {
    const maliciousBuffer = await createDemoSampleApk('MALICIOUS_SBI_TROJAN');
    const report = await inspectApkFile(maliciousBuffer, 'sbi-kyc-update.apk');

    expect(report.overallScore).toBeGreaterThanOrEqual(67);
    expect(report.verdict).toBe('CRITICAL_MALWARE_RISK');
    expect(report.riskLevel).toBe('HIGH');

    // Check detected dangerous permissions
    const permNames = report.detectedPermissions.map((p) => p.name);
    expect(permNames).toContain('android.permission.BIND_ACCESSIBILITY_SERVICE');
    expect(permNames).toContain('android.permission.RECEIVE_SMS');
    expect(permNames).toContain('android.permission.READ_SMS');
    expect(permNames).toContain('android.permission.SYSTEM_ALERT_WINDOW');

    // Check 6 SpotTheScam dimensions
    expect(report.dimensions.appIdentity.status).toBe('CRITICAL');
    expect(report.dimensions.permissionRisk.status).toBe('CRITICAL');
    expect(report.dimensions.certificateTrust.status).toBe('CRITICAL');
    expect(report.dimensions.targetSdk.status).toBe('CRITICAL');

    expect(report.sha256Hash).toBeDefined();
    expect(report.suspiciousSignals.length).toBeGreaterThan(0);
    expect(report.recommendations.length).toBeGreaterThan(0);
  });

  it('correctly scores a clean application with normal permissions as safe', async () => {
    const cleanBuffer = await createDemoSampleApk('BENIGN_CALCULATOR');
    const report = await inspectApkFile(cleanBuffer, 'calculator.apk');

    expect(report.overallScore).toBeLessThan(34);
    expect(report.verdict).toBe('CLEAN_APPLICATION');
    expect(report.riskLevel).toBe('LOW');

    expect(report.detectedPermissions).toHaveLength(0);
    expect(report.dimensions.permissionRisk.status).toBe('GOOD');
    expect(report.dimensions.certificateTrust.status).toBe('GOOD');
  });

  it('rejects corrupt or non-zip buffers with clear error message', async () => {
    const corruptBuffer = new Uint8Array([1, 2, 3, 4, 5, 6]).buffer;
    await expect(inspectApkFile(corruptBuffer, 'invalid.apk')).rejects.toThrow('INVALID_APK_FILE');
  });
});
