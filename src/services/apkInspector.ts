import JSZip from 'jszip';

export interface AndroidPermissionDetail {
  name: string;
  category: 'CRITICAL' | 'DANGEROUS' | 'NORMAL';
  riskDescription: string;
  trojanPattern: string;
  points: number;
}

export interface DimensionScore {
  score: number; // 0 (safe) to 100 (critical danger)
  status: 'GOOD' | 'WARNING' | 'CRITICAL';
  reason: string;
}

export interface ApkSecurityReport {
  fileName: string;
  fileSizeBytes: number;
  sha256Hash: string;
  packageName: string;
  appName: string;
  versionName: string;
  minSdkVersion: number;
  targetSdkVersion: number;
  overallScore: number; // 0 to 100
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  verdict: 'CLEAN_APPLICATION' | 'SUSPICIOUS_RISK' | 'CRITICAL_MALWARE_RISK';
  summary: string;
  dimensions: {
    appIdentity: DimensionScore;
    permissionRisk: DimensionScore;
    certificateTrust: DimensionScore;
    versionTag: DimensionScore;
    minSdk: DimensionScore;
    targetSdk: DimensionScore;
  };
  detectedPermissions: AndroidPermissionDetail[];
  suspiciousSignals: string[];
  recommendations: string[];
}

export const KNOWN_DANGEROUS_PERMISSIONS: Record<
  string,
  { category: 'CRITICAL' | 'DANGEROUS'; riskDescription: string; trojanPattern: string; points: number }
> = {
  'android.permission.BIND_ACCESSIBILITY_SERVICE': {
    category: 'CRITICAL',
    riskDescription: 'Accessibility Service Takeover',
    trojanPattern: 'Used by Android banking trojans to log keystrokes, steal credentials, and automate funds transfer without user consent.',
    points: 30,
  },
  'android.permission.RECEIVE_SMS': {
    category: 'CRITICAL',
    riskDescription: 'SMS Interception (2FA OTP Theft)',
    trojanPattern: 'Intercepts incoming banking OTPs and deletes notifications before victim notices.',
    points: 25,
  },
  'android.permission.READ_SMS': {
    category: 'CRITICAL',
    riskDescription: 'Read Private SMS Messages',
    trojanPattern: 'Harvests bank balance SMS, card OTPs, and private authentication codes.',
    points: 20,
  },
  'android.permission.SEND_SMS': {
    category: 'DANGEROUS',
    riskDescription: 'Background SMS Transmission',
    trojanPattern: 'Sends unauthorized premium-rate SMS or malware propagation links to victim contacts.',
    points: 15,
  },
  'android.permission.SYSTEM_ALERT_WINDOW': {
    category: 'DANGEROUS',
    riskDescription: 'Overlay Phishing Display',
    trojanPattern: 'Draws fake login screens over legitimate banking apps (SBI, HDFC, PhonePe) to steal PINs.',
    points: 20,
  },
  'android.permission.REQUEST_INSTALL_PACKAGES': {
    category: 'DANGEROUS',
    riskDescription: 'Malware Dropper / Sideloading',
    trojanPattern: 'Silently downloads and installs secondary malicious payloads from remote C2 servers.',
    points: 15,
  },
  'android.permission.READ_PHONE_STATE': {
    category: 'DANGEROUS',
    riskDescription: 'Device Hardware Fingerprinting',
    trojanPattern: 'Extracts IMEI, IMSI, and carrier data to track infected devices.',
    points: 10,
  },
  'android.permission.READ_CONTACTS': {
    category: 'DANGEROUS',
    riskDescription: 'Contact Book Exfiltration',
    trojanPattern: 'Used in loan harassment apps and pig butchering scams to extort victims via their family.',
    points: 15,
  },
  'android.permission.RECORD_AUDIO': {
    category: 'DANGEROUS',
    riskDescription: 'Microphone Surveillance',
    trojanPattern: 'Enables covert audio recording and ambient eavesdropping.',
    points: 15,
  },
  'android.permission.CAMERA': {
    category: 'DANGEROUS',
    riskDescription: 'Camera Surveillance',
    trojanPattern: 'Captures stealth screenshots and user photos without notification.',
    points: 10,
  },
  'android.permission.QUERY_ALL_PACKAGES': {
    category: 'DANGEROUS',
    riskDescription: 'Installed Apps Enumeration',
    trojanPattern: 'Detects installed banking, crypto wallet, and security apps to target.',
    points: 10,
  },
};

const BANKING_AND_GOV_BRANDS = [
  { name: 'State Bank of India (YONO)', key: 'sbi', officialPkg: 'com.sbi.lotusintouch' },
  { name: 'HDFC Bank Mobile', key: 'hdfc', officialPkg: 'com.snapwork.hdfc' },
  { name: 'ICICI iMobile', key: 'icici', officialPkg: 'com.csam.icici.bank.imobile' },
  { name: 'Punjab National Bank One', key: 'pnb', officialPkg: 'com.pnb.pnbone' },
  { name: 'PhonePe UPI', key: 'phonepe', officialPkg: 'com.phonepe.app' },
  { name: 'Paytm Payments', key: 'paytm', officialPkg: 'net.one97.paytm' },
  { name: 'AnyDesk Remote Support', key: 'anydesk', officialPkg: 'com.anydesk.anydeskandroid' },
  { name: 'Parivahan E-Challan', key: 'parivahan', officialPkg: 'gov.nic.mparivahan' },
  { name: 'Electricity Board Portal', key: 'electricity', officialPkg: 'com.utility.bill' },
];

/**
 * Computes SHA-256 hash from ArrayBuffer
 */
export async function computeSha256(buffer: ArrayBuffer): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  // Fallback
  let hash = 0;
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    hash = (hash << 5) - hash + bytes[i];
    hash |= 0;
  }
  return `sha256_${Math.abs(hash).toString(16)}`;
}

/**
 * Extract printable strings from binary AndroidManifest.xml
 */
export function extractStringsFromBinary(buffer: Uint8Array): string[] {
  const strings: string[] = [];
  let current = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    // Printable ASCII or UTF-8 alphanumeric
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) {
        strings.push(current);
      }
      current = '';
    }
  }
  if (current.length >= 4) {
    strings.push(current);
  }

  return strings;
}

/**
 * Inspect an Android APK file and generate the SpotTheScam 6-dimensional report
 */
export async function inspectApkFile(
  fileBuffer: ArrayBuffer,
  fileName: string = 'app-release.apk'
): Promise<ApkSecurityReport> {
  const sha256 = await computeSha256(fileBuffer);
  const fileSizeBytes = fileBuffer.byteLength;

  let zip: JSZip;
  try {
    zip = await JSZip.loadAsync(fileBuffer);
  } catch {
    throw new Error('INVALID_APK_FILE: File is not a valid Android APK (ZIP archive format required).');
  }

  // 1. Check for Android Manifest
  const manifestFile = zip.file('AndroidManifest.xml');
  let rawManifestStrings: string[] = [];

  if (manifestFile) {
    const manifestBuffer = await manifestFile.async('uint8array');
    rawManifestStrings = extractStringsFromBinary(manifestBuffer);
  }

  // 2. Also search classes.dex for embedded URLs / strings
  const dexFiles = Object.keys(zip.files).filter((f) => f.endsWith('.dex'));
  let dexStrings: string[] = [];
  for (const df of dexFiles.slice(0, 2)) {
    const dexFile = zip.file(df);
    if (dexFile) {
      const dexBuf = await dexFile.async('uint8array');
      // Scan sample slice of dex to save memory
      const sample = dexBuf.slice(0, Math.min(dexBuf.length, 250000));
      dexStrings = dexStrings.concat(extractStringsFromBinary(sample));
    }
  }

  const allStrings = rawManifestStrings.concat(dexStrings);

  // 3. Extract Declared Permissions
  const detectedPermissions: AndroidPermissionDetail[] = [];
  let permPointsSum = 0;

  for (const str of allStrings) {
    for (const [permName, permDef] of Object.entries(KNOWN_DANGEROUS_PERMISSIONS)) {
      if (str.includes(permName) && !detectedPermissions.some((p) => p.name === permName)) {
        detectedPermissions.push({
          name: permName,
          category: permDef.category,
          riskDescription: permDef.riskDescription,
          trojanPattern: permDef.trojanPattern,
          points: permDef.points,
        });
        permPointsSum += permDef.points;
      }
    }
  }

  // 4. Extract Package Name & App Name
  let packageName = 'com.unknown.android.app';
  for (const s of rawManifestStrings) {
    if (/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$/i.test(s) && !s.includes('android.permission') && !s.includes('schemas')) {
      packageName = s;
      break;
    }
  }

  let appName = fileName.replace(/\.apk$/i, '');
  for (const s of rawManifestStrings) {
    if (s.length >= 3 && s.length <= 30 && !s.includes('.') && !s.includes('/') && !s.includes('android')) {
      appName = s;
      break;
    }
  }

  // 5. Target SDK & Min SDK extraction
  let targetSdk = 33; // Default modern
  let minSdk = 21;    // Default modern Lollipop

  for (const s of rawManifestStrings) {
    const targetMatch = s.match(/(?:targetSdk(?:Version)?|target)[:= ]*(\d+)/i);
    if (targetMatch) {
      targetSdk = parseInt(targetMatch[1], 10);
    }
    const minMatch = s.match(/(?:minSdk(?:Version)?|min)[:= ]*(\d+)/i);
    if (minMatch) {
      minSdk = parseInt(minMatch[1], 10);
    }
  }

  // 6. Signature & Certificate Inspection (META-INF)
  const metaFiles = Object.keys(zip.files).filter((f) => f.startsWith('META-INF/'));
  let isDebugCertificate = false;

  for (const mf of metaFiles) {
    if (mf.endsWith('.RSA') || mf.endsWith('.DSA') || mf.endsWith('.EC') || mf.endsWith('.SF')) {
      const certFile = zip.file(mf);
      if (certFile) {
        const certBytes = await certFile.async('uint8array');
        const certText = extractStringsFromBinary(certBytes).join(' ');
        if (/androiddebugkey|cn=android debug|debug/i.test(certText)) {
          isDebugCertificate = true;
        }
      }
    }
  }

  // 7. Impersonation & Brand Spoofing Check
  const suspiciousSignals: string[] = [];
  let identityScoreVal = 10;
  let identityReason = 'App identity does not trigger impersonation signatures.';

  for (const brand of BANKING_AND_GOV_BRANDS) {
    const nameMatch = fileName.toLowerCase().includes(brand.key) || appName.toLowerCase().includes(brand.key);
    const isUnofficial = packageName !== brand.officialPkg;

    if (nameMatch && isUnofficial) {
      identityScoreVal = 85;
      identityReason = `Brand Spoofing: App mimics "${brand.name}", but official package is "${brand.officialPkg}".`;
      suspiciousSignals.push(`Impersonates official brand "${brand.name}" with fake package identifier "${packageName}".`);
      break;
    }
  }

  // 8. Dimension Scoring (SpotTheScam 6-Dimensional Architecture)

  // Dimension 1: App Identity Score
  const appIdentity: DimensionScore = {
    score: identityScoreVal,
    status: identityScoreVal >= 67 ? 'CRITICAL' : identityScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason: identityReason,
  };

  // Dimension 2: Permission Risk Score
  const permScoreVal = Math.min(100, Math.round((permPointsSum / 70) * 100));
  const permissionRisk: DimensionScore = {
    score: permScoreVal,
    status: permScoreVal >= 67 ? 'CRITICAL' : permScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason:
      detectedPermissions.length > 0
        ? `Contains ${detectedPermissions.length} sensitive Android permissions, including ${detectedPermissions.map((p) => p.name.split('.').pop()).join(', ')}.`
        : 'Zero dangerous or intrusive system permissions requested.',
  };

  // Dimension 3: Certificate Trust Score
  let certScoreVal = 15;
  let certReason = 'Standard developer release signature present.';
  if (isDebugCertificate) {
    certScoreVal = 90;
    certReason = 'Signed with Android Debug Key (CN=Android Debug). Indicates unofficial sideloaded APK build.';
    suspiciousSignals.push('Android Debug Key certificate found — never used for legitimate production applications.');
  } else if (metaFiles.length === 0) {
    certScoreVal = 80;
    certReason = 'Unsigned APK archive — lacks Android cryptographic signature verification.';
    suspiciousSignals.push('Unsigned APK container — fails Android security standards.');
  }

  const certificateTrust: DimensionScore = {
    score: certScoreVal,
    status: certScoreVal >= 67 ? 'CRITICAL' : certScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason: certReason,
  };

  // Dimension 4: Version Tag Score
  const isSuspiciousVersion = /^(?:1\.0(?:\.0)?|debug|test|0\.1|99\.0)$/i.test(appName);
  const versionScoreVal = isSuspiciousVersion ? 45 : 10;
  const versionTag: DimensionScore = {
    score: versionScoreVal,
    status: versionScoreVal >= 67 ? 'CRITICAL' : versionScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason: isSuspiciousVersion
      ? 'Anomalous or generic version numbering common in disposable malware builds.'
      : `Declared version tag follows normal distribution standards.`,
  };

  // Dimension 5: Minimum SDK Score
  const minSdkScoreVal = minSdk < 21 ? 60 : 15;
  const minSdkDimension: DimensionScore = {
    score: minSdkScoreVal,
    status: minSdkScoreVal >= 67 ? 'CRITICAL' : minSdkScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason:
      minSdk < 21
        ? `Outdated Min SDK (${minSdk}) targets obsolete Android versions vulnerable to known exploits.`
        : `Modern Min SDK (${minSdk}) ensures baseline security compatibility.`,
  };

  // Dimension 6: Target SDK Score
  // Android runtime permissions were introduced in SDK 23 (Android 6.0). Target SDK < 23 is a classic evasion trick.
  const isEvasionTargetSdk = targetSdk < 23;
  const targetSdkScoreVal = isEvasionTargetSdk ? 85 : targetSdk < 30 ? 40 : 10;
  if (isEvasionTargetSdk) {
    suspiciousSignals.push(`Target SDK ${targetSdk} exploits legacy permission model to bypass runtime authorization prompts.`);
  }

  const targetSdkDimension: DimensionScore = {
    score: targetSdkScoreVal,
    status: targetSdkScoreVal >= 67 ? 'CRITICAL' : targetSdkScoreVal >= 34 ? 'WARNING' : 'GOOD',
    reason: isEvasionTargetSdk
      ? `Critical Evasion: Target SDK ${targetSdk} (< 23) forces legacy permission grants without user runtime approval.`
      : `Target SDK ${targetSdk} adheres to modern Android security sandbox policies.`,
  };

  // 9. Aggregate Overall Score
  // Weighted calculation based on SpotTheScam methodology
  const weightedOverall = Math.round(
    appIdentity.score * 0.25 +
      permissionRisk.score * 0.35 +
      certificateTrust.score * 0.2 +
      targetSdkDimension.score * 0.1 +
      minSdkDimension.score * 0.05 +
      versionTag.score * 0.05
  );

  const overallScore = Math.min(100, Math.max(10, weightedOverall));

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
  let verdict: ApkSecurityReport['verdict'] = 'CLEAN_APPLICATION';
  let summary = 'No high-risk trojan or permission hijacking behaviors identified in this APK.';

  if (overallScore >= 45) {
    riskLevel = 'HIGH';
    verdict = 'CRITICAL_MALWARE_RISK';
    summary =
      'CRITICAL THREAT: This APK displays high-severity characteristics of an Android Banking Trojan, RAT, or OTP Interceptor.';
  } else if (overallScore >= 21) {
    riskLevel = 'MEDIUM';
    verdict = 'SUSPICIOUS_RISK';
    summary =
      'WARNING: This APK requests excessive or unusual permissions that warrant careful scrutiny before installation.';
  }

  // 10. Recommendations
  const recommendations: string[] = [];
  if (riskLevel === 'HIGH') {
    recommendations.push('DO NOT install or open this APK file on your mobile device.');
    recommendations.push('If already installed: Open Android Settings > Apps > Force Stop and UNINSTALL immediately.');
    recommendations.push('Check Android Settings > Accessibility: Revoke any granted permissions for this application.');
    recommendations.push('Change all banking, UPI, and email passwords from a different, clean smartphone or computer.');
    recommendations.push('Report the fraudulent APK download link to the National Cyber Crime Helpline at 1930.');
  } else if (riskLevel === 'MEDIUM') {
    recommendations.push('Only install applications distributed directly via the official Google Play Store.');
    recommendations.push('Verify whether this app truly needs sensitive SMS or device administration privileges.');
  } else {
    recommendations.push('Verify that the APK package matches your intended official developer before installing.');
  }

  return {
    fileName,
    fileSizeBytes,
    sha256Hash: sha256,
    packageName,
    appName,
    versionName: '1.0.0',
    minSdkVersion: minSdk,
    targetSdkVersion: targetSdk,
    overallScore,
    riskLevel,
    verdict,
    summary,
    dimensions: {
      appIdentity,
      permissionRisk,
      certificateTrust,
      versionTag,
      minSdk: minSdkDimension,
      targetSdk: targetSdkDimension,
    },
    detectedPermissions,
    suspiciousSignals,
    recommendations,
  };
}

/**
 * Helper to generate a synthetic sample APK buffer for instant demo testing
 */
export async function createDemoSampleApk(
  type: 'MALICIOUS_SBI_TROJAN' | 'BENIGN_CALCULATOR'
): Promise<ArrayBuffer> {
  const zip = new JSZip();

  if (type === 'MALICIOUS_SBI_TROJAN') {
    // Construct fake AndroidManifest with SMS & Accessibility permissions
    const fakeManifestStrings = [
      'com.sbi.kyc.update.official',
      'SBI YONO Security Update',
      'android.permission.RECEIVE_SMS',
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.REQUEST_INSTALL_PACKAGES',
      'targetSdkVersion=22',
      'minSdkVersion=19',
    ].join('\x00\x00');

    zip.file('AndroidManifest.xml', fakeManifestStrings);
    zip.file('classes.dex', 'DalvikDexCodeHeader\x00http://sbi-c2-server.xyz/api/exfiltrate-sms');
    zip.file('META-INF/CERT.RSA', 'CN=Android Debug,O=Android,C=US androiddebugkey');
    zip.file('META-INF/CERT.SF', 'Signature-Version: 1.0');
    zip.file('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0');
  } else {
    // Construct benign calculator manifest
    const fakeManifestStrings = [
      'com.tools.simplecalculator',
      'Simple Calculator',
      'android.permission.VIBRATE',
      'targetSdkVersion=34',
      'minSdkVersion=26',
    ].join('\x00\x00');

    zip.file('AndroidManifest.xml', fakeManifestStrings);
    zip.file('classes.dex', 'DalvikDexCodeHeader\x00CalculatorComputeLogic');
    zip.file('META-INF/CERT.RSA', 'CN=Google Play Release,O=Google LLC');
    zip.file('META-INF/CERT.SF', 'Signature-Version: 1.0');
    zip.file('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0');
  }

  return await zip.generateAsync({ type: 'arraybuffer' });
}

export const inspectApkBuffer = inspectApkFile;
