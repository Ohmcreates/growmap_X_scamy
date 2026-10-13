import { BENCHMARK_CORPUS, computeBenchmarkMetrics } from '../engine/benchmarks.js';
import { detectScript } from '../engine/multilingual.js';
import { generateSafeNextSteps } from '../engine/safeSteps.js';
import { analyzeMessage } from '../engine/scorer.js';
import { ScanResult } from '../engine/types.js';
import { AiAdvisorService } from '../services/aiAdvisor.js';
import { HistoryService } from '../services/history.js';
import { OcrService } from '../services/ocr.js';
import { IndicatorType, ReportingService, VerifiedIndicator } from '../services/reporting.js';
import { renderPricingModal, renderUnmatchedChecks } from './cards.js';
import { renderDashboardHtml } from './dashboard.js';
import { checkWebsiteUrl } from '../engine/websiteChecker.js';
import { mergeHighlightSpans, renderHighlightedDom } from './highlighter.js';
import { inspectApkBuffer, createDemoSampleApk, ApkSecurityReport } from '../services/apkInspector.js';
import {
  inspectFileVirusTotal,
  createVirusTotalDemoBuffer,
  KNOWN_THREAT_HASHES,
  SECURITY_VENDORS,
  VirusTotalReport,
} from '../services/virusTotalInspector.js';

export function initApp() {
  // Navigation & Theme Elements
  const btnThemeToggle = document.getElementById('btnThemeToggle') as HTMLButtonElement;
  const btnSearchNav = document.getElementById('btnSearchNav') as HTMLButtonElement;
  const navHowItWorks = document.getElementById('navHowItWorks') as HTMLAnchorElement;
  const navPricing = document.getElementById('navPricing') as HTMLAnchorElement;
  const navThreatDb = document.getElementById('navThreatDb') as HTMLAnchorElement;
  const navEvaluation = document.getElementById('navEvaluation') as HTMLAnchorElement;

  // Sidebar Elements
  const menuScanMessage = document.getElementById('menuScanMessage') as HTMLButtonElement;
  const menuScanLink = document.getElementById('menuScanLink') as HTMLButtonElement;
  const menuScanImage = document.getElementById('menuScanImage') as HTMLButtonElement;
  const menuScanApk = document.getElementById('menuScanApk') as HTMLButtonElement;
  const menuScanVt = document.getElementById('menuScanVt') as HTMLButtonElement;
  const menuThreatDb = document.getElementById('menuThreatDb') as HTMLButtonElement;
  const menuEvaluation = document.getElementById('menuEvaluation') as HTMLButtonElement;
  const menuHistory = document.getElementById('menuHistory') as HTMLButtonElement;
  const menuLearn = document.getElementById('menuLearn') as HTMLButtonElement;
  const menuReport = document.getElementById('menuReport') as HTMLButtonElement;
  const btnViewPlansSidebar = document.getElementById('btnViewPlansSidebar') as HTMLButtonElement;

  // Input Tabs & Panels
  const tabTextMessage = document.getElementById('tabTextMessage') as HTMLButtonElement;
  const tabScanLink = document.getElementById('tabScanLink') as HTMLButtonElement;
  const tabUploadImage = document.getElementById('tabUploadImage') as HTMLButtonElement;
  const tabApkScan = document.getElementById('tabApkScan') as HTMLButtonElement;
  const tabVtScan = document.getElementById('tabVtScan') as HTMLButtonElement;

  const panelTextMessage = document.getElementById('panelTextMessage') as HTMLElement;
  const panelScanLink = document.getElementById('panelScanLink') as HTMLElement;
  const panelUploadImage = document.getElementById('panelUploadImage') as HTMLElement;
  const panelApkScan = document.getElementById('panelApkScan') as HTMLElement;
  const panelVtScan = document.getElementById('panelVtScan') as HTMLElement;

  const textarea = document.getElementById('messageInput') as HTMLTextAreaElement;
  const urlInput = document.getElementById('urlInput') as HTMLInputElement;
  const charCounter = document.getElementById('charCounter') as HTMLElement;
  const inlineError = document.getElementById('inlineError') as HTMLElement;
  const ocrStatusNotice = document.getElementById('ocrStatusNotice') as HTMLElement;
  const apkStatusNotice = document.getElementById('apkStatusNotice') as HTMLElement;
  const vtStatusNotice = document.getElementById('vtStatusNotice') as HTMLElement;
  const langScriptPill = document.getElementById('langScriptPill') as HTMLElement;

  const dropZone = document.getElementById('dropZone') as HTMLElement;
  const btnBrowseOcr = document.getElementById('btnBrowseOcr') as HTMLButtonElement;
  const ocrFileInput = document.getElementById('ocrFileInput') as HTMLInputElement;

  // APK DropZone & Demo Test Buttons
  const apkDropZone = document.getElementById('apkDropZone') as HTMLElement;
  const btnBrowseApk = document.getElementById('btnBrowseApk') as HTMLButtonElement;
  const apkFileInput = document.getElementById('apkFileInput') as HTMLInputElement;
  const btnApkDemoTrojan = document.getElementById('btnApkDemoTrojan') as HTMLButtonElement;
  const btnApkDemoClean = document.getElementById('btnApkDemoClean') as HTMLButtonElement;

  // APK Inspector Elements (SpotTheScam 6-Dimensional Model)
  const apkInspectorCard = document.getElementById('apkInspectorCard') as HTMLElement;
  const apkNameText = document.getElementById('apkNameText') as HTMLElement;
  const apkPackageText = document.getElementById('apkPackageText') as HTMLElement;
  const apkScoreBadge = document.getElementById('apkScoreBadge') as HTMLElement;
  const apkVerdictBadge = document.getElementById('apkVerdictBadge') as HTMLElement;
  const apkSha256Text = document.getElementById('apkSha256Text') as HTMLElement;
  const apkSummaryText = document.getElementById('apkSummaryText') as HTMLElement;

  const dimAppIdScore = document.getElementById('dimAppIdScore') as HTMLElement;
  const dimAppIdReason = document.getElementById('dimAppIdReason') as HTMLElement;
  const dimPermScore = document.getElementById('dimPermScore') as HTMLElement;
  const dimPermReason = document.getElementById('dimPermReason') as HTMLElement;
  const dimCertScore = document.getElementById('dimCertScore') as HTMLElement;
  const dimCertReason = document.getElementById('dimCertReason') as HTMLElement;
  const dimTargetSdkScore = document.getElementById('dimTargetSdkScore') as HTMLElement;
  const dimTargetSdkReason = document.getElementById('dimTargetSdkReason') as HTMLElement;
  const dimMinSdkScore = document.getElementById('dimMinSdkScore') as HTMLElement;
  const dimMinSdkReason = document.getElementById('dimMinSdkReason') as HTMLElement;
  const dimVersionScore = document.getElementById('dimVersionScore') as HTMLElement;
  const dimVersionReason = document.getElementById('dimVersionReason') as HTMLElement;

  const apkPermissionsList = document.getElementById('apkPermissionsList') as HTMLElement;
  const apkRecommendationsList = document.getElementById('apkRecommendationsList') as HTMLElement;

  // VirusTotal File & Hash Scan Elements
  const vtDropZone = document.getElementById('vtDropZone') as HTMLElement;
  const btnBrowseVtFile = document.getElementById('btnBrowseVtFile') as HTMLButtonElement;
  const vtFileInput = document.getElementById('vtFileInput') as HTMLInputElement;
  const vtHashSearchInput = document.getElementById('vtHashSearchInput') as HTMLInputElement;
  const btnSearchVtHash = document.getElementById('btnSearchVtHash') as HTMLButtonElement;
  const btnVtDemoRansomware = document.getElementById('btnVtDemoRansomware') as HTMLButtonElement;
  const btnVtDemoDropper = document.getElementById('btnVtDemoDropper') as HTMLButtonElement;
  const btnVtDemoClean = document.getElementById('btnVtDemoClean') as HTMLButtonElement;

  const vtInspectorCard = document.getElementById('vtInspectorCard') as HTMLElement;
  const vtFileNameText = document.getElementById('vtFileNameText') as HTMLElement;
  const vtFileMetaText = document.getElementById('vtFileMetaText') as HTMLElement;
  const vtRatioCircle = document.getElementById('vtRatioCircle') as HTMLElement;
  const vtRatioScore = document.getElementById('vtRatioScore') as HTMLElement;
  const vtRatioTotal = document.getElementById('vtRatioTotal') as HTMLElement;
  const vtVerdictTitle = document.getElementById('vtVerdictTitle') as HTMLElement;
  const vtClassificationText = document.getElementById('vtClassificationText') as HTMLElement;

  const vtTabDetection = document.getElementById('vtTabDetection') as HTMLButtonElement;
  const vtTabDetails = document.getElementById('vtTabDetails') as HTMLButtonElement;
  const vtTabBehavior = document.getElementById('vtTabBehavior') as HTMLButtonElement;
  const vtTabProtocol = document.getElementById('vtTabProtocol') as HTMLButtonElement;

  const vtPanelDetection = document.getElementById('vtPanelDetection') as HTMLElement;
  const vtPanelDetails = document.getElementById('vtPanelDetails') as HTMLElement;
  const vtPanelBehavior = document.getElementById('vtPanelBehavior') as HTMLElement;
  const vtPanelProtocol = document.getElementById('vtPanelProtocol') as HTMLElement;

  const vtVendorSummaryCounts = document.getElementById('vtVendorSummaryCounts') as HTMLElement;
  const vtVendorsGrid = document.getElementById('vtVendorsGrid') as HTMLElement;

  const vtMd5Text = document.getElementById('vtMd5Text') as HTMLElement;
  const vtSha1Text = document.getElementById('vtSha1Text') as HTMLElement;
  const vtSha256Text = document.getElementById('vtSha256Text') as HTMLElement;
  const vtFileTypeVal = document.getElementById('vtFileTypeVal') as HTMLElement;
  const vtMagicVal = document.getElementById('vtMagicVal') as HTMLElement;
  const vtEntropyFill = document.getElementById('vtEntropyFill') as HTMLElement;
  const vtEntropyScoreVal = document.getElementById('vtEntropyScoreVal') as HTMLElement;
  const vtEntropyRatingVal = document.getElementById('vtEntropyRatingVal') as HTMLElement;
  const vtEntropyExplainVal = document.getElementById('vtEntropyExplainVal') as HTMLElement;

  const vtBehaviorSignalsList = document.getElementById('vtBehaviorSignalsList') as HTMLElement;
  const vtNetworkList = document.getElementById('vtNetworkList') as HTMLElement;
  const vtRecommendationsList = document.getElementById('vtRecommendationsList') as HTMLElement;

  // Example Buttons (English + Multilingual Hinglish & Hindi)
  const btnExampleSbi = document.getElementById('btnExampleSbi') as HTMLButtonElement;
  const btnExampleDelivery = document.getElementById('btnExampleDelivery') as HTMLButtonElement;
  const btnExampleInvestment = document.getElementById('btnExampleInvestment') as HTMLButtonElement;
  const btnExampleJob = document.getElementById('btnExampleJob') as HTMLButtonElement;
  const btnExampleDigitalArrest = document.getElementById('btnExampleDigitalArrest') as HTMLButtonElement;
  const btnExampleHinglish = document.getElementById('btnExampleHinglish') as HTMLButtonElement;
  const btnExampleHindi = document.getElementById('btnExampleHindi') as HTMLButtonElement;

  // Submit & Clear
  const btnAnalyze = document.getElementById('btnAnalyze') as HTMLButtonElement;
  const btnClearInput = document.getElementById('btnClearInput') as HTMLButtonElement;

  // Results Section
  const analysisResultCard = document.getElementById('analysisResultCard') as HTMLElement;
  const scamArchetypeBanner = document.getElementById('scamArchetypeBanner') as HTMLElement;
  const archetypeName = document.getElementById('archetypeName') as HTMLElement;
  const archetypeDesc = document.getElementById('archetypeDesc') as HTMLElement;
  const archetypeAdvice = document.getElementById('archetypeAdvice') as HTMLElement;

  const highlightedTextBox = document.getElementById('highlightedTextBox') as HTMLElement;
  const warningSignsMount = document.getElementById('warningSignsMount') as HTMLElement;
  const unmatchedMount = document.getElementById('unmatchedMount') as HTMLElement;
  const btnCopyHighlights = document.getElementById('btnCopyHighlights') as HTMLButtonElement;

  // Website Inspector Elements (IsThisSpam Reverse Engineered)
  const websiteInspectorCard = document.getElementById('websiteInspectorCard') as HTMLElement;
  const webDomainText = document.getElementById('webDomainText') as HTMLElement;
  const webConfidenceBadge = document.getElementById('webConfidenceBadge') as HTMLElement;
  const webVerdictBadge = document.getElementById('webVerdictBadge') as HTMLElement;
  const webSummaryText = document.getElementById('webSummaryText') as HTMLElement;
  const webMetricAge = document.getElementById('webMetricAge') as HTMLElement;
  const webMetricTld = document.getElementById('webMetricTld') as HTMLElement;
  const webMetricSsl = document.getElementById('webMetricSsl') as HTMLElement;
  const webMetricBlacklist = document.getElementById('webMetricBlacklist') as HTMLElement;
  const webThreatsList = document.getElementById('webThreatsList') as HTMLElement;
  const webRecommendationsList = document.getElementById('webRecommendationsList') as HTMLElement;

  const btnUrlSbiPhish = document.getElementById('btnUrlSbiPhish') as HTMLButtonElement;
  const btnUrlChallanPhish = document.getElementById('btnUrlChallanPhish') as HTMLButtonElement;
  const btnUrlShortener = document.getElementById('btnUrlShortener') as HTMLButtonElement;
  const btnUrlOfficialSbi = document.getElementById('btnUrlOfficialSbi') as HTMLButtonElement;

  // AI Safety Assistant Elements
  const assistantResponseBox = document.getElementById('assistantResponseBox') as HTMLElement;
  const assistantQueryInput = document.getElementById('assistantQueryInput') as HTMLInputElement;
  const btnSendAssistantQuery = document.getElementById('btnSendAssistantQuery') as HTMLButtonElement;

  // Model Feedback Bar
  const btnFeedbackYes = document.getElementById('btnFeedbackYes') as HTMLButtonElement;
  const btnFeedbackNo = document.getElementById('btnFeedbackNo') as HTMLButtonElement;
  const btnOpenModelEval = document.getElementById('btnOpenModelEval') as HTMLButtonElement;
  const feedbackNotice = document.getElementById('feedbackNotice') as HTMLElement;

  // Right Column Widgets
  const donutArc = document.getElementById('donutArc') as unknown as SVGCircleElement;
  const gaugeScoreNum = document.getElementById('gaugeScoreNum') as HTMLElement;
  const riskLevelPill = document.getElementById('riskLevelPill') as HTMLElement;
  const riskSummaryText = document.getElementById('riskSummaryText') as HTMLElement;
  const whyMattersText = document.getElementById('whyMattersText') as HTMLElement;
  const safeNextStepsMount = document.getElementById('safeNextStepsMount') as HTMLElement;
  const btnShareScore = document.getElementById('btnShareScore') as HTMLButtonElement;

  // Full-Screen Alarm Overlay
  const screenAlarmOverlay = document.getElementById('screenAlarmOverlay') as HTMLElement;
  const alarmTitle = document.getElementById('alarmTitle') as HTMLElement;
  const alarmSubtitle = document.getElementById('alarmSubtitle') as HTMLElement;
  const alarmIcon = document.getElementById('alarmIcon') as HTMLElement;
  const btnDismissAlarm = document.getElementById('btnDismissAlarm') as HTMLButtonElement;

  // Modals
  const dashboardModal = document.getElementById('dashboardModal') as HTMLElement;
  const threatDbModal = document.getElementById('threatDbModal') as HTMLElement;
  const evalModal = document.getElementById('evalModal') as HTMLElement;
  const historyModal = document.getElementById('historyModal') as HTMLElement;
  const pricingModal = document.getElementById('pricingModal') as HTMLElement;
  const reportModal = document.getElementById('reportModal') as HTMLElement;
  const learnModal = document.getElementById('learnModal') as HTMLElement;

  const closeDashboardModal = document.getElementById('closeDashboardModal') as HTMLButtonElement;
  const closeThreatDbModal = document.getElementById('closeThreatDbModal') as HTMLButtonElement;
  const closeEvalModal = document.getElementById('closeEvalModal') as HTMLButtonElement;
  const closeHistoryModal = document.getElementById('closeHistoryModal') as HTMLButtonElement;
  const closePricingModal = document.getElementById('closePricingModal') as HTMLButtonElement;
  const closeReportModal = document.getElementById('closeReportModal') as HTMLButtonElement;
  const closeLearnModal = document.getElementById('closeLearnModal') as HTMLButtonElement;

  const dashboardMount = document.getElementById('dashboardMount') as HTMLElement;
  const threatDbSearchInput = document.getElementById('threatDbSearchInput') as HTMLInputElement;
  const threatDbResultsMount = document.getElementById('threatDbResultsMount') as HTMLElement;
  const evalMetricsMount = document.getElementById('evalMetricsMount') as HTMLElement;
  const historyListMount = document.getElementById('historyListMount') as HTMLElement;
  const btnClearHistory = document.getElementById('btnClearHistory') as HTMLButtonElement;
  const pricingMount = document.getElementById('pricingMount') as HTMLElement;

  const reportForm = document.getElementById('reportForm') as HTMLFormElement;
  const reportType = document.getElementById('reportType') as HTMLSelectElement;
  const reportValue = document.getElementById('reportValue') as HTMLInputElement;
  const reportCategory = document.getElementById('reportCategory') as HTMLInputElement;
  const reportSuccess = document.getElementById('reportSuccess') as HTMLElement;

  let currentResult: ScanResult | null = null;
  let activeTab: 'TEXT' | 'LINK' | 'IMAGE' | 'APK' | 'VT' = 'TEXT';
  let alarmInterval: number | null = null;
  let alarmTimeout: number | null = null;

  // --------------------------------------------------------------------------
  // Theme Toggle (Light / Dark)
  // --------------------------------------------------------------------------
  btnThemeToggle?.addEventListener('click', () => {
    document.body.classList.toggle('theme-dark');
    const isDark = document.body.classList.contains('theme-dark');
    btnThemeToggle.textContent = isDark ? '🌙' : '☀️';
  });

  // --------------------------------------------------------------------------
  // Tab Switching
  // --------------------------------------------------------------------------
  function switchTab(tab: 'TEXT' | 'LINK' | 'IMAGE' | 'APK' | 'VT') {
    activeTab = tab;

    [tabTextMessage, tabScanLink, tabUploadImage, tabApkScan, tabVtScan].forEach((t) => t?.classList.remove('active'));
    [panelTextMessage, panelScanLink, panelUploadImage, panelApkScan, panelVtScan].forEach((p) => {
      if (p) p.style.display = 'none';
    });

    [menuScanMessage, menuScanLink, menuScanImage, menuScanApk, menuScanVt].forEach((m) => m?.classList.remove('active'));

    if (tab === 'TEXT') {
      tabTextMessage?.classList.add('active');
      menuScanMessage?.classList.add('active');
      if (panelTextMessage) panelTextMessage.style.display = 'block';
      textarea?.focus();
    } else if (tab === 'LINK') {
      tabScanLink?.classList.add('active');
      menuScanLink?.classList.add('active');
      if (panelScanLink) panelScanLink.style.display = 'block';
      urlInput?.focus();
    } else if (tab === 'IMAGE') {
      tabUploadImage?.classList.add('active');
      menuScanImage?.classList.add('active');
      if (panelUploadImage) panelUploadImage.style.display = 'block';
    } else if (tab === 'APK') {
      tabApkScan?.classList.add('active');
      menuScanApk?.classList.add('active');
      if (panelApkScan) panelApkScan.style.display = 'block';
    } else if (tab === 'VT') {
      tabVtScan?.classList.add('active');
      menuScanVt?.classList.add('active');
      if (panelVtScan) panelVtScan.style.display = 'block';
    }
  }

  tabTextMessage?.addEventListener('click', () => switchTab('TEXT'));
  tabScanLink?.addEventListener('click', () => switchTab('LINK'));
  tabUploadImage?.addEventListener('click', () => switchTab('IMAGE'));
  tabApkScan?.addEventListener('click', () => switchTab('APK'));
  tabVtScan?.addEventListener('click', () => switchTab('VT'));

  menuScanMessage?.addEventListener('click', () => switchTab('TEXT'));
  menuScanLink?.addEventListener('click', () => switchTab('LINK'));
  menuScanImage?.addEventListener('click', () => switchTab('IMAGE'));
  menuScanApk?.addEventListener('click', () => switchTab('APK'));
  menuScanVt?.addEventListener('click', () => switchTab('VT'));

  // --------------------------------------------------------------------------
  // Multilingual Script Detection & Character Counter
  // --------------------------------------------------------------------------
  function updateInputMetrics() {
    const text = textarea.value;
    const len = text.length;
    charCounter.textContent = `${len.toLocaleString()}/2000`;

    if (text.trim().length > 0) {
      const scriptInfo = detectScript(text);
      if (scriptInfo.script === 'DEVANAGARI') {
        langScriptPill.textContent = '🌐 Script: Devanagari (हिन्दी)';
      } else if (scriptInfo.isHinglishCandidate) {
        langScriptPill.textContent = '🌐 Script: Hinglish (Transliteration)';
      } else if (scriptInfo.script === 'MIXED') {
        langScriptPill.textContent = '🌐 Script: Mixed Multilingual';
      } else {
        langScriptPill.textContent = '🌐 Script: Latin (English)';
      }
    } else {
      langScriptPill.textContent = '🌐 Script: Latin (English)';
    }
  }

  textarea.addEventListener('input', () => {
    updateInputMetrics();
    inlineError.style.display = 'none';
  });

  textarea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis();
    }
  });

  btnClearInput?.addEventListener('click', () => {
    textarea.value = '';
    urlInput.value = '';
    updateInputMetrics();
    inlineError.style.display = 'none';
    ocrStatusNotice.style.display = 'none';
    analysisResultCard.style.display = 'none';
    resetScoreWidgets();
  });

  // --------------------------------------------------------------------------
  // Example Buttons (English + Multilingual)
  // --------------------------------------------------------------------------
  btnExampleSbi?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.example/verify and share the OTP you receive to confirm.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleDelivery?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Your package delivery has been held at customs due to unpaid duty of Rs 25. Pay immediately within 24 hours at http://india-post-parcel.xyz/pay to avoid cancellation.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleInvestment?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Exclusive invitation: Guaranteed 300% returns in 7 days! Join VIP Telegram crypto trading group for daily profits. Transfer Rs 5,000 to initiate automated trading robot.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleJob?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Part-time work from home opportunity! Earn Rs 3,500 daily just by liking YouTube videos and rating hotels on Telegram. Contact manager immediately to receive bonus.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleDigitalArrest?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'URGENT NOTICE: CBI and Cyber Crime Branch issued a Digital Arrest warrant against your Aadhaar card for illegal narcotics parcel. You must stay on Skype video call statement immediately or police will arrive.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleHinglish?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Aapka SBI bank account aaj block ho jayega KYC update na hone par. Turant link kholein http://sbi-kyc-update.example/login aur OTP share karein.';
    updateInputMetrics();
    runAnalysis();
  });

  btnExampleHindi?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'प्रिय ग्राहक, आपका बिजली बिल बकाया है। आज रात 9:30 बजे बिजली का कनेक्शन काट दिया जाएगा। तुरंत बिजली अधिकारी को 9876543210 पर कॉल करें।';
    updateInputMetrics();
    runAnalysis();
  });

  btnUrlSbiPhish?.addEventListener('click', () => {
    switchTab('LINK');
    urlInput.value = 'http://sbi-kyc-update.xyz/login';
    runAnalysis();
  });

  btnUrlChallanPhish?.addEventListener('click', () => {
    switchTab('LINK');
    urlInput.value = 'http://echallan-parivahan-gov.in.xyz';
    runAnalysis();
  });

  btnUrlShortener?.addEventListener('click', () => {
    switchTab('LINK');
    urlInput.value = 'http://bit.ly/indpst-fee';
    runAnalysis();
  });

  btnUrlOfficialSbi?.addEventListener('click', () => {
    switchTab('LINK');
    urlInput.value = 'https://sbi.co.in';
    runAnalysis();
  });

  // --------------------------------------------------------------------------
  // Full-Screen Blinking Alarm System (5–10 Seconds)
  // --------------------------------------------------------------------------
  function triggerScreenAlarm(level: 'RED' | 'YELLOW' | 'GREEN', score: number, durationSeconds: number = 7) {
    dismissScreenAlarm();

    screenAlarmOverlay.className = 'screen-alarm-overlay';
    screenAlarmOverlay.style.display = 'flex';

    if (level === 'RED') {
      screenAlarmOverlay.classList.add('alarm-red');
      alarmIcon.textContent = '🚨';
      alarmTitle.textContent = 'CRITICAL HIGH RISK SCAM DETECTED';
      alarmSubtitle.innerHTML = `Score: <strong>${score}/100</strong> • Full-Screen Alert Active (<span id="alarmCountdown">${durationSeconds}</span>s)`;
    } else if (level === 'YELLOW') {
      screenAlarmOverlay.classList.add('alarm-yellow');
      alarmIcon.textContent = '⚠️';
      alarmTitle.textContent = 'SUSPICIOUS WARNING SIGNS DETECTED';
      alarmSubtitle.innerHTML = `Score: <strong>${score}/100</strong> • Caution Alert Active (<span id="alarmCountdown">${durationSeconds}</span>s)`;
    } else {
      screenAlarmOverlay.classList.add('alarm-green');
      alarmIcon.textContent = '✅';
      alarmTitle.textContent = 'VERIFIED SAFE / CLEAN MESSAGE';
      alarmSubtitle.innerHTML = `Score: <strong>${score}/100</strong> • Safety Notice Active (<span id="alarmCountdown">${durationSeconds}</span>s)`;
    }

    let remaining = durationSeconds;
    alarmInterval = window.setInterval(() => {
      remaining -= 1;
      const cd = document.getElementById('alarmCountdown');
      if (cd) cd.textContent = String(Math.max(0, remaining));

      if (remaining <= 0) {
        dismissScreenAlarm();
      }
    }, 1000);

    alarmTimeout = window.setTimeout(() => {
      dismissScreenAlarm();
    }, durationSeconds * 1000);
  }

  function dismissScreenAlarm() {
    if (alarmInterval) clearInterval(alarmInterval);
    if (alarmTimeout) clearTimeout(alarmTimeout);
    alarmInterval = null;
    alarmTimeout = null;
    screenAlarmOverlay.style.display = 'none';
    screenAlarmOverlay.className = 'screen-alarm-overlay';
  }

  btnDismissAlarm?.addEventListener('click', dismissScreenAlarm);

  // --------------------------------------------------------------------------
  // Core Analysis Engine Flow
  // --------------------------------------------------------------------------
  btnAnalyze?.addEventListener('click', runAnalysis);

  function runAnalysis() {
    let rawText = '';
    if (activeTab === 'LINK') {
      rawText = urlInput.value.trim();
      if (rawText && !rawText.startsWith('http')) {
        rawText = `https://${rawText}`;
      }
    } else {
      rawText = textarea.value.trim();
    }

    if (!rawText) {
      inlineError.style.display = 'block';
      if (activeTab === 'LINK') urlInput.focus();
      else textarea.focus();
      return;
    }
    inlineError.style.display = 'none';

    // 1. Execute deterministic heuristics engine
    const result = analyzeMessage(rawText);
    currentResult = result;

    // 2. Persist to private local history
    HistoryService.saveScan(rawText, result);

    // 3. Trigger 5-10 Second Full-Screen Blinking Alarm
    if (result.score >= 60) {
      triggerScreenAlarm('RED', result.score, 7);
    } else if (result.score >= 30) {
      triggerScreenAlarm('YELLOW', result.score, 7);
    } else {
      triggerScreenAlarm('GREEN', result.score, 7);
    }

    // 4. Update Right Column Widgets
    updateScoreWidgets(result);

    // 5. Update Analysis Result Card & Specialized Classifiers
    updateAnalysisCard(rawText, result);

    // 6. Reset Feedback bar
    feedbackNotice.style.display = 'none';

    // 7. Reveal results and smooth scroll
    analysisResultCard.style.display = 'flex';
    analysisResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function resetScoreWidgets() {
    gaugeScoreNum.textContent = '0';
    donutArc.style.strokeDashoffset = '251.2';
    donutArc.style.stroke = 'var(--accent-red)';
    riskLevelPill.className = 'risk-badge-pill low';
    riskLevelPill.textContent = 'Low Risk';
    riskSummaryText.textContent = 'Paste a message and click Analyze to view verified warning signs and score.';
  }

  function updateScoreWidgets(result: ScanResult) {
    const totalCircumference = 251.2;
    const progressOffset = totalCircumference - (totalCircumference * result.score) / 100;
    donutArc.style.strokeDashoffset = `${Math.max(0, progressOffset)}`;

    gaugeScoreNum.textContent = `${result.score}`;

    if (result.riskLevel === 'HIGH') {
      donutArc.style.stroke = '#ef4444';
      riskLevelPill.className = 'risk-badge-pill high';
      riskLevelPill.textContent = 'High Risk';
      riskSummaryText.textContent =
        result.summary ||
        'This message shows multiple signs of a scam. Do not share any personal information.';
      whyMattersText.textContent =
        'Scammers use urgent wording, fake account threats, and suspicious links to create fear and trick you into sharing sensitive information like OTPs or passwords.';
    } else if (result.riskLevel === 'MEDIUM') {
      donutArc.style.stroke = '#f59e0b';
      riskLevelPill.className = 'risk-badge-pill medium';
      riskLevelPill.textContent = 'Medium Risk';
      riskSummaryText.textContent =
        result.summary ||
        'This message shows suspicious warning signs. Treat links and unexpected instructions with caution.';
      whyMattersText.textContent =
        'Unverified payment links, shorteners, or unexpected delivery fees are typical methods used by phishing campaigns to steal credentials.';
    } else {
      donutArc.style.stroke = '#22c55e';
      riskLevelPill.className = 'risk-badge-pill low';
      riskLevelPill.textContent = 'Low Risk';
      riskSummaryText.textContent =
        result.summary ||
        'No common scam warning signs detected. Legitimate format and sender structure.';
      whyMattersText.textContent =
        'Legitimate bank and service messages never ask for OTPs, CVVs, or immediate transfers over unsolicited links.';
    }

    const firedIds = new Set(result.breakdown.map((b) => b.ruleId));
    const steps = generateSafeNextSteps(firedIds, result.riskLevel);
    safeNextStepsMount.innerHTML = steps
      .map(
        (s, idx) => `
      <div class="safe-step-item">
        <span class="step-num-badge">${idx + 1}</span>
        <div class="step-text"><strong>${s.verb}:</strong> ${s.instruction}</div>
      </div>
    `
      )
      .join('');
  }

  function updateAnalysisCard(rawText: string, result: ScanResult) {
    // Feature 3: Specialized Scam Classifiers Attribution
    if (result.scamProfile) {
      scamArchetypeBanner.style.display = 'flex';
      archetypeName.textContent = result.scamProfile.name;
      archetypeDesc.textContent = result.scamProfile.description;
      archetypeAdvice.innerHTML = `
        <strong>🛡️ Tailored Protocol for this Scam Pattern:</strong>
        <ul>
          ${(result.scamProfile.advicePayload || []).map((a: string) => `<li>${a}</li>`).join('')}
        </ul>
      `;
    } else {
      scamArchetypeBanner.style.display = 'none';
    }

    // Website & URL Safety Inspector (Reverse Engineered from IsThisSpam)
    const isUrl =
      activeTab === 'LINK' ||
      /^(?:https?:\/\/|\bwww\.|\b[a-z0-9-]+\.(?:com|org|in|net|xyz|top|live|click|gov\.in)\b)/i.test(rawText.trim());

    if (isUrl && websiteInspectorCard) {
      const webResult = checkWebsiteUrl(rawText);
      websiteInspectorCard.style.display = 'flex';
      webDomainText.textContent = webResult.domain;
      webConfidenceBadge.textContent = `Confidence: ${(webResult.confidence * 100).toFixed(0)}%`;

      if (webResult.classification === 'SCAM_DETECTED') {
        webVerdictBadge.className = 'web-verdict-pill danger';
        webVerdictBadge.textContent = '🚨 SCAM WEBSITE';
      } else if (webResult.classification === 'SUSPICIOUS_DETECTED') {
        webVerdictBadge.className = 'web-verdict-pill warning';
        webVerdictBadge.textContent = '⚠️ SUSPICIOUS WEBSITE';
      } else if (webResult.classification === 'OFFICIAL_DOMAIN_VERIFIED') {
        webVerdictBadge.className = 'web-verdict-pill success';
        webVerdictBadge.textContent = '🛡️ OFFICIAL BRAND';
      } else {
        webVerdictBadge.className = 'web-verdict-pill success';
        webVerdictBadge.textContent = '✅ NO KNOWN THREATS';
      }

      webSummaryText.textContent = webResult.summary;
      webMetricAge.textContent = webResult.metrics.domainAgeEstimate;
      webMetricTld.textContent =
        webResult.metrics.tldRisk === 'HIGH'
          ? `High-Risk Disposable (.${webResult.tld})`
          : `Standard / Trusted (.${webResult.tld})`;
      webMetricSsl.textContent = webResult.metrics.sslStatus;
      webMetricBlacklist.textContent = webResult.metrics.threatDbListed
        ? '⚠️ Blacklisted in Community DB'
        : 'Clean (No Threat Feed Flags)';

      if (webResult.threats.length > 0) {
        webThreatsList.innerHTML = webResult.threats
          .map(
            (t) => `
            <div class="web-threat-item">
              <span class="web-threat-badge">${t.severity}</span>
              <div class="web-threat-text">
                <strong>${t.title}</strong>
                <p>${t.detail}</p>
              </div>
            </div>
          `
          )
          .join('');
      } else {
        webThreatsList.innerHTML = `
          <div style="font-size: 0.85rem; color: #16a34a; padding: 6px 0;">
            ✓ No suspicious domain signals found. Verified safe infrastructure.
          </div>
        `;
      }

      webRecommendationsList.innerHTML = webResult.recommendations
        .map((rec) => `<li>${rec}</li>`)
        .join('');
    } else if (websiteInspectorCard) {
      websiteInspectorCard.style.display = 'none';
    }

    if (apkInspectorCard) {
      apkInspectorCard.style.display = 'none';
    }

    if (vtInspectorCard) {
      vtInspectorCard.style.display = 'none';
    }

    // Evidence Highlighting
    const mergedSpans = mergeHighlightSpans(rawText, result.activeEvidence);
    highlightedTextBox.innerHTML = '';
    const highlightedDom = renderHighlightedDom(rawText, mergedSpans, (ruleId) => {
      const targetRow = document.getElementById(`sign-${ruleId}`);
      if (targetRow) {
        targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
        targetRow.style.backgroundColor = 'var(--accent-red-soft)';
        setTimeout(() => {
          targetRow.style.backgroundColor = '#ffffff';
        }, 1800);
      }
    });
    highlightedTextBox.appendChild(highlightedDom);

    // Warning Signs List
    if (result.breakdown.length === 0) {
      warningSignsMount.innerHTML = `
        <div style="padding: 14px; text-align: center; color: var(--text-muted); font-size: 0.88rem;">
          ✓ Zero suspicious warning signs detected. All heuristic checks passed cleanly.
        </div>
      `;
    } else {
      warningSignsMount.innerHTML = result.breakdown
        .map((item) => {
          const icon = getRuleIcon(item.ruleId);
          const evidenceQuote = item.evidence
            .map((e) => `"${escapeHtml(e.matchedText)}"`)
            .slice(0, 2)
            .join(', ');

          return `
          <div class="warning-sign-row" id="sign-${item.ruleId}">
            <div class="sign-left-cluster">
              <span class="sign-icon">${icon}</span>
              <span class="sign-label">${item.label}</span>
              <span class="sign-evidence-quote">${evidenceQuote}</span>
            </div>
            <span class="sign-points-badge ${item.cappedByGroup ? 'capped' : ''}">
              ${item.cappedByGroup ? '+0' : `+${item.awardedPoints}`}
            </span>
          </div>
        `;
        })
        .join('');
    }

    // Unmatched Checks Drawer
    unmatchedMount.innerHTML = renderUnmatchedChecks(result.unmatchedRules);

    // Reset Assistant Output
    assistantResponseBox.style.display = 'none';
  }

  function getRuleIcon(ruleId: string): string {
    if (ruleId.includes('URGENCY') || ruleId.includes('DEADLINE')) return '❗';
    if (ruleId.includes('ACCOUNT') || ruleId.includes('ARREST') || ruleId.includes('THREAT')) return '🏛️';
    if (ruleId.includes('LINK') || ruleId.includes('DOMAIN') || ruleId.includes('SHORTENER')) return '🔗';
    if (ruleId.includes('OTP') || ruleId.includes('PASSWORD') || ruleId.includes('CREDENTIAL')) return '🔒';
    if (ruleId.includes('UPI') || ruleId.includes('MONEY') || ruleId.includes('COLLECT')) return '💳';
    if (ruleId.includes('BAIT') || ruleId.includes('REWARD') || ruleId.includes('JOB')) return '🎁';
    return '⚠️';
  }

  // --------------------------------------------------------------------------
  // Feature 4: Interactive AI Safety Assistant
  // --------------------------------------------------------------------------
  function answerSafetyAssistant(question: string) {
    assistantResponseBox.style.display = 'block';
    assistantResponseBox.innerHTML = '⏳ <em>Consulting safety guidelines with PII masking...</em>';

    // Mask sensitive details
    const sanitizedQuery = AiAdvisorService.maskPii(question);
    const qLower = sanitizedQuery.toLowerCase();

    setTimeout(() => {
      let advice = '';

      if (qLower.includes('video') || qLower.includes('skype') || qLower.includes('call') || qLower.includes('arrest')) {
        advice = `
          <strong>🛑 Do NOT answer or continue any video call.</strong><br>
          Indian law enforcement agencies (CBI, ED, Cyber Police) <strong>never</strong> interrogate citizens or issue 'Digital Arrest' orders over Skype or WhatsApp video calls. Hang up immediately, block the caller, and report to <strong>1930</strong>.
        `;
      } else if (qLower.includes('money') || qLower.includes('paid') || qLower.includes('transfer') || qLower.includes('refund')) {
        advice = `
          <strong>⏱️ Act within the Golden Hour (2–4 hours):</strong><br>
          Dial <strong>1930</strong> (National Cyber Crime Helpline) immediately. The helpline coordinates with bank nodal officers to issue an emergency freeze on the recipient account/UPI VPA before the fraudster can cash out.
        `;
      } else if (qLower.includes('police') || qLower.includes('report') || qLower.includes('complain')) {
        advice = `
          <strong>📢 Official Reporting Channels:</strong><br>
          1. File a cyber complaint at <a href="https://cybercrime.gov.in" target="_blank" style="color: var(--accent-red); font-weight: bold;">cybercrime.gov.in</a> with SMS/call screenshots.<br>
          2. Report the fraud mobile number on the Government of India Sanchar Saathi portal (<a href="https://sancharsaathi.gov.in" target="_blank" style="color: var(--accent-red);">sancharsaathi.gov.in</a>) to revoke the fraudster's SIM card.
        `;
      } else if (qLower.includes('click') || qLower.includes('link') || qLower.includes('open')) {
        advice = `
          <strong>⚠️ Do NOT click or open the link.</strong><br>
          Phishing links can silently trigger malware APK downloads or steal session cookies. If you already opened the link, clear your browser cookies, disconnect mobile data/Wi-Fi temporarily, and do not enter any credentials.
        `;
      } else {
        advice = `
          <strong>🛡️ Safety Assessment:</strong><br>
          This message triggered <strong>${currentResult?.breakdown.length || 0} warning signals</strong>. As a primary rule: never share OTPs, PINs, or bank account numbers. Contact the institution only through verified phone numbers printed on the physical card or official website.
        `;
      }

      assistantResponseBox.innerHTML = `
        <div style="margin-bottom: 6px;"><strong>Question:</strong> <em>"${escapeHtml(sanitizedQuery)}"</em></div>
        <div>${advice}</div>
      `;
    }, 450);
  }

  // Quick Prompt Chips
  document.querySelectorAll('.prompt-chip').forEach((chip) => {
    chip.addEventListener('click', (e) => {
      const q = (e.currentTarget as HTMLElement).getAttribute('data-q');
      if (q) {
        answerSafetyAssistant(q);
      }
    });
  });

  btnSendAssistantQuery?.addEventListener('click', () => {
    const q = assistantQueryInput.value.trim();
    if (q) {
      answerSafetyAssistant(q);
      assistantQueryInput.value = '';
    }
  });

  assistantQueryInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      const q = assistantQueryInput.value.trim();
      if (q) {
        answerSafetyAssistant(q);
        assistantQueryInput.value = '';
      }
    }
  });

  // --------------------------------------------------------------------------
  // Feature 5: Model Evaluation & User Feedback
  // --------------------------------------------------------------------------
  btnFeedbackYes?.addEventListener('click', () => {
    feedbackNotice.style.display = 'block';
    feedbackNotice.textContent = '✓ Thank you! Detection confirmed as accurate.';
    try {
      localStorage.setItem(`feedback_${Date.now()}`, 'ACCURATE');
    } catch {}
  });

  btnFeedbackNo?.addEventListener('click', () => {
    feedbackNotice.style.display = 'block';
    feedbackNotice.textContent = '✓ Feedback recorded. Flagged for heuristic calibration review.';
    try {
      localStorage.setItem(`feedback_${Date.now()}`, 'FALSE_ALARM');
    } catch {}
  });

  function openModelEvaluationModal() {
    const metrics = computeBenchmarkMetrics((text) => analyzeMessage(text));

    evalMetricsMount.innerHTML = `
      <div class="eval-stats-grid">
        <div class="eval-stat-card">
          <div class="eval-stat-num" style="color: #16a34a;">${metrics.precision}%</div>
          <div class="eval-stat-label">Precision (Target ≥98%)</div>
        </div>
        <div class="eval-stat-card">
          <div class="eval-stat-num" style="color: #16a34a;">${metrics.recall}%</div>
          <div class="eval-stat-label">Recall (Target ≥95%)</div>
        </div>
        <div class="eval-stat-card">
          <div class="eval-stat-num" style="color: #0f172a;">${metrics.fpr}%</div>
          <div class="eval-stat-label">False Positive Rate</div>
        </div>
        <div class="eval-stat-card">
          <div class="eval-stat-num" style="color: #0f172a;">${metrics.totalSamples}</div>
          <div class="eval-stat-label">Benchmark Corpus</div>
        </div>
      </div>

      <div class="confusion-matrix-box">
        <strong>Confusion Matrix (100 Samples: 50 Scams, 50 Benign Controls):</strong>
        <table class="cm-table">
          <thead>
            <tr>
              <th></th>
              <th>Predicted Scam (Med/High)</th>
              <th>Predicted Benign (Low)</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th>Actual Scam (50)</th>
              <td style="color: #16a34a; font-weight: bold;">True Positives: ${metrics.tp}</td>
              <td style="color: #dc2626;">False Negatives: ${metrics.fn}</td>
            </tr>
            <tr>
              <th>Actual Benign (50)</th>
              <td style="color: #dc2626;">False Positives: ${metrics.fp} (High FP: ${metrics.highFalsePositives})</td>
              <td style="color: #16a34a; font-weight: bold;">True Negatives: ${metrics.tn}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div>
        <h4 style="margin-bottom: 8px;">Standardized Test Corpus Explorer:</h4>
        <div class="benchmark-table-wrap">
          <table class="benchmark-samples-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Category</th>
                <th>Sample Message</th>
                <th>Expected Risk</th>
              </tr>
            </thead>
            <tbody>
              ${BENCHMARK_CORPUS.slice(0, 30)
                .map(
                  (c) => `
                <tr>
                  <td><code>${c.id}</code></td>
                  <td><strong>${c.category}</strong></td>
                  <td>${escapeHtml(c.text.slice(0, 85))}...</td>
                  <td><span class="threat-badge-pill ${c.category === 'SCAM' ? 'verified' : 'review'}">${c.expectedMinRisk || c.expectedMaxRisk || 'LOW'}</span></td>
                </tr>
              `
                )
                .join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;

    evalModal.classList.add('open');
  }

  btnOpenModelEval?.addEventListener('click', openModelEvaluationModal);
  menuEvaluation?.addEventListener('click', openModelEvaluationModal);
  navEvaluation?.addEventListener('click', (e) => {
    e.preventDefault();
    openModelEvaluationModal();
  });
  closeEvalModal?.addEventListener('click', () => evalModal.classList.remove('open'));

  // --------------------------------------------------------------------------
  // Feature 1: Scam Reporting & Verified Indicator Database
  // --------------------------------------------------------------------------
  function renderThreatDatabase(filterQuery = '') {
    const defaultBad = ReportingService.getKnownBadIndicators();
    let storedReports: VerifiedIndicator[] = [];
    try {
      const stored = localStorage.getItem('scam_spotter_reports_v1');
      if (stored) {
        const parsed = JSON.parse(stored);
        storedReports = parsed.map((r: { type: IndicatorType; normalizedValue: string; category: string; reportedAt: string }) => ({
          type: r.type,
          normalizedValue: r.normalizedValue,
          status: 'UNDER_REVIEW',
          threatLevel: 'HIGH',
          source: `Community Report (${r.category})`,
          verifiedAt: r.reportedAt,
        }));
      }
    } catch {}

    const allIndicators = [...defaultBad, ...storedReports];
    const q = filterQuery.toLowerCase().trim();

    const filtered = allIndicators.filter(
      (ind) =>
        ind.normalizedValue.toLowerCase().includes(q) ||
        ind.type.toLowerCase().includes(q) ||
        ind.source.toLowerCase().includes(q)
    );

    if (filtered.length === 0) {
      threatDbResultsMount.innerHTML = `
        <div style="padding: 20px; text-align: center; color: var(--text-muted);">
          No matching indicators found for "${escapeHtml(filterQuery)}".
        </div>
      `;
      return;
    }

    threatDbResultsMount.innerHTML = filtered
      .map(
        (ind) => `
      <div class="threat-indicator-row">
        <div>
          <span class="threat-val-mono">${escapeHtml(ind.normalizedValue)}</span>
          <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">
            ${ind.type} • Source: ${escapeHtml(ind.source)} • Verified: ${new Date(ind.verifiedAt).toLocaleDateString()}
          </div>
        </div>
        <div style="display: flex; gap: 6px; align-items: center;">
          <span class="threat-badge-pill ${ind.status === 'VERIFIED' ? 'verified' : 'review'}">
            ${ind.status}
          </span>
          <span class="threat-badge-pill verified">
            ${ind.threatLevel}
          </span>
        </div>
      </div>
    `
      )
      .join('');
  }

  function openThreatDatabaseModal() {
    threatDbSearchInput.value = '';
    renderThreatDatabase('');
    threatDbModal.classList.add('open');
  }

  threatDbSearchInput?.addEventListener('input', () => {
    renderThreatDatabase(threatDbSearchInput.value);
  });

  menuThreatDb?.addEventListener('click', openThreatDatabaseModal);
  navThreatDb?.addEventListener('click', (e) => {
    e.preventDefault();
    openThreatDatabaseModal();
  });
  closeThreatDbModal?.addEventListener('click', () => threatDbModal.classList.remove('open'));

  // --------------------------------------------------------------------------
  // Copy Buttons
  // --------------------------------------------------------------------------
  btnCopyHighlights?.addEventListener('click', async () => {
    if (!currentResult) return;
    try {
      await navigator.clipboard.writeText(textarea.value.trim());
      btnCopyHighlights.textContent = '✓';
      setTimeout(() => {
        btnCopyHighlights.textContent = '📋';
      }, 2000);
    } catch {
      alert('Could not copy to clipboard.');
    }
  });

  btnShareScore?.addEventListener('click', async () => {
    if (!currentResult) return;
    const summary = [
      '🛡️ SCAMY FRAUD ANALYSIS',
      `Score: ${currentResult.score}/100 (${currentResult.riskLevel} RISK)`,
      currentResult.scamProfile ? `Identified Archetype: ${currentResult.scamProfile.name}` : '',
      `Warning Signs: ${currentResult.breakdown.map((b) => b.label).join(', ')}`,
      'Emergency Helpline: 1930 (cybercrime.gov.in)',
    ]
      .filter(Boolean)
      .join('\n');

    try {
      await navigator.clipboard.writeText(summary);
      btnShareScore.textContent = '✓';
      setTimeout(() => {
        btnShareScore.textContent = '🔗';
      }, 2000);
    } catch {
      alert('Analysis summary:\n\n' + summary);
    }
  });

  // --------------------------------------------------------------------------
  // OCR & QR Code Flow
  // --------------------------------------------------------------------------
  async function handleOcrFile(file: File | Blob) {
    ocrStatusNotice.style.display = 'block';
    ocrStatusNotice.className = 'ocr-status-notice ocr-loading';
    ocrStatusNotice.innerHTML = '⏳ Preprocessing screenshot and decoding QR code / text...';

    try {
      const ocrResult = await OcrService.extractTextFromImage(file, (progress, status) => {
        ocrStatusNotice.innerHTML = `⏳ ${status} (${progress}%)`;
      });

      switchTab('TEXT');
      textarea.value = ocrResult.text;
      updateInputMetrics();

      if (ocrResult.qrPayload) {
        ocrStatusNotice.className = 'ocr-status-notice ocr-success';
        ocrStatusNotice.innerHTML = `✓ <strong>QR Code Decoded:</strong> Embedded link/UPI extracted. Running fraud scan...`;
        runAnalysis();
      } else if (ocrResult.lowConfidence && ocrResult.notice) {
        ocrStatusNotice.className = 'ocr-status-notice ocr-warning';
        ocrStatusNotice.innerHTML = `⚠️ ${ocrResult.notice}`;
      } else {
        ocrStatusNotice.className = 'ocr-status-notice ocr-success';
        ocrStatusNotice.innerHTML = `✓ Text extracted (${Math.round(ocrResult.confidence)}% confidence). Click Analyze Message.`;
      }
    } catch (err) {
      console.error('OCR failed:', err);
      ocrStatusNotice.className = 'ocr-status-notice ocr-error';
      ocrStatusNotice.innerHTML = '❌ Could not extract text from this image. Please paste text directly.';
    }
  }

  btnBrowseOcr?.addEventListener('click', () => ocrFileInput?.click());
  ocrFileInput?.addEventListener('change', () => {
    if (ocrFileInput.files && ocrFileInput.files[0]) {
      const chosen = ocrFileInput.files[0];
      if (chosen.name.toLowerCase().endsWith('.apk') || chosen.type.includes('package-archive')) {
        switchTab('APK');
        handleApkFile(chosen);
      } else {
        handleOcrFile(chosen);
      }
    }
  });

  dropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--accent-red)';
  });
  dropZone?.addEventListener('dragleave', () => {
    dropZone.style.borderColor = 'var(--border-color)';
  });
  dropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0];
      if (droppedFile.name.toLowerCase().endsWith('.apk') || droppedFile.type.includes('package-archive')) {
        switchTab('APK');
        handleApkFile(droppedFile);
      } else {
        handleOcrFile(droppedFile);
      }
    }
  });

  // --------------------------------------------------------------------------
  // SpotTheScam.in Android APK Security Inspector Flow
  // --------------------------------------------------------------------------
  async function renderApkReport(report: ApkSecurityReport) {
    if (!apkInspectorCard) return;

    // 1. Hide other cards & show APK card
    if (websiteInspectorCard) websiteInspectorCard.style.display = 'none';
    if (scamArchetypeBanner) scamArchetypeBanner.style.display = 'none';
    if (vtInspectorCard) vtInspectorCard.style.display = 'none';
    apkInspectorCard.style.display = 'flex';

    // 2. Populate Identity & Verification Badges
    apkNameText.textContent = report.appName || report.fileName;
    apkPackageText.textContent = report.packageName || 'Unknown Package';
    apkSha256Text.textContent = report.sha256Hash;
    apkScoreBadge.textContent = `Malware Risk: ${report.overallScore}/100`;

    if (report.verdict === 'CRITICAL_MALWARE_RISK') {
      apkVerdictBadge.className = 'web-verdict-pill danger';
      apkVerdictBadge.textContent = '🚨 CRITICAL MALWARE';
    } else if (report.verdict === 'SUSPICIOUS_RISK') {
      apkVerdictBadge.className = 'web-verdict-pill warning';
      apkVerdictBadge.textContent = '⚠️ SUSPICIOUS APK';
    } else {
      apkVerdictBadge.className = 'web-verdict-pill success';
      apkVerdictBadge.textContent = '✅ CLEAN APPLICATION';
    }

    apkSummaryText.textContent = report.summary;

    // 3. Render 6-Dimensional Security Audit Dimensions (SpotTheScam.in Model)
    const dims = [
      { elScore: dimAppIdScore, elReason: dimAppIdReason, data: report.dimensions.appIdentity },
      { elScore: dimPermScore, elReason: dimPermReason, data: report.dimensions.permissionRisk },
      { elScore: dimCertScore, elReason: dimCertReason, data: report.dimensions.certificateTrust },
      { elScore: dimTargetSdkScore, elReason: dimTargetSdkReason, data: report.dimensions.targetSdk },
      { elScore: dimMinSdkScore, elReason: dimMinSdkReason, data: report.dimensions.minSdk },
      { elScore: dimVersionScore, elReason: dimVersionReason, data: report.dimensions.versionTag },
    ];

    dims.forEach(({ elScore, elReason, data }) => {
      if (elScore && elReason && data) {
        elScore.className = `dim-score-pill ${
          data.status === 'CRITICAL' ? 'danger' : data.status === 'WARNING' ? 'warning' : 'safe'
        }`;
        elScore.textContent = `${data.status} (${data.score}/100)`;
        elReason.textContent = data.reason;
      }
    });

    // 4. Render Detected Dangerous Permissions
    if (report.detectedPermissions.length > 0) {
      apkPermissionsList.innerHTML = report.detectedPermissions
        .map(
          (p) => `
          <div class="apk-perm-item ${p.category.toLowerCase()}">
            <div class="apk-perm-top">
              <span class="apk-perm-name">${escapeHtml(p.name)}</span>
              <span class="apk-perm-badge">${p.category} (+${p.points})</span>
            </div>
            <strong style="font-size: 0.8rem; margin: 2px 0;">${escapeHtml(p.riskDescription)}</strong>
            <p class="apk-trojan-pattern">${escapeHtml(p.trojanPattern)}</p>
          </div>
        `
        )
        .join('');
    } else {
      apkPermissionsList.innerHTML = `
        <div style="font-size: 0.85rem; color: #16a34a; padding: 6px 0;">
          ✓ No dangerous or trojan permissions requested. Standard sandboxed capability.
        </div>
      `;
    }

    // 5. Render Emergency Recommendations
    apkRecommendationsList.innerHTML = report.recommendations
      .map((rec) => `<li>${escapeHtml(rec)}</li>`)
      .join('');

    // 6. Sync Original Message box & Warnings table
    highlightedTextBox.innerHTML = `
      <div style="font-family: var(--font-mono); font-size: 0.82rem; background: var(--bg-card-subtle); padding: 10px; border-radius: 6px; line-height: 1.6;">
        <strong>[Android APK Binary Analysis]</strong> ${escapeHtml(report.fileName)} (${(report.fileSizeBytes / 1024).toFixed(1)} KB)<br>
        <strong>Package:</strong> <code>${escapeHtml(report.packageName)}</code> | <strong>Target SDK:</strong> <code>${report.targetSdkVersion}</code> | <strong>Min SDK:</strong> <code>${report.minSdkVersion}</code><br>
        <strong>SHA-256 Fingerprint:</strong> <code>${escapeHtml(report.sha256Hash)}</code>
      </div>
    `;

    warningSignsMount.innerHTML = report.detectedPermissions
      .map(
        (p) => `
        <div class="warning-sign-row">
          <div class="sign-left-cluster">
            <span class="sign-icon">📱</span>
            <span class="sign-label">${escapeHtml(p.riskDescription)}</span>
            <span class="sign-evidence-quote">"${escapeHtml(p.name)}"</span>
          </div>
          <span class="sign-points-badge">+${p.points}</span>
        </div>
      `
      )
      .join('');

    // 7. Update Score Gauge & Widgets
    const fakeScanResult: ScanResult = {
      score: report.overallScore,
      riskLevel: report.riskLevel,
      headline:
        report.verdict === 'CRITICAL_MALWARE_RISK'
          ? 'Critical Android Malware Risk Detected'
          : report.verdict === 'SUSPICIOUS_RISK'
          ? 'Suspicious Android Application'
          : 'Clean Android Package',
      summary: report.summary,
      breakdown: report.detectedPermissions.map((p) => ({
        ruleId: p.name,
        label: `${p.riskDescription} (${p.category})`,
        group: 'credential' as const,
        rawPoints: p.points,
        awardedPoints: p.points,
        category: 'MALWARE_PERMISSION',
        cappedByGroup: false,
        explanation: p.trojanPattern,
        evidence: [
          {
            ruleId: p.name,
            ruleLabel: p.riskDescription,
            group: 'credential' as const,
            matchedText: p.name,
            startIndex: 0,
            endIndex: p.name.length,
            negated: false,
            category: 'MALWARE_PERMISSION',
          },
        ],
      })),
      unmatchedRules: [],
      allEvidence: [],
      activeEvidence: [],
      negatedEvidence: [],
      rawScore: report.overallScore,
      advice: report.recommendations[0] || 'Inspect application before installation.',
      floorApplied: report.overallScore >= 67,
      metadata: {
        characterCount: report.fileSizeBytes,
        scannedAt: new Date().toISOString(),
        engineVersion: '2.4.0-spotthescam',
        totalChecksRun: 6,
      },
    };

    currentResult = fakeScanResult;
    updateScoreWidgets(fakeScanResult);

    // 8. Save Scan in Private History
    HistoryService.saveScan(`[APK Scan] ${report.appName} (${report.fileName})`, fakeScanResult);

    // 9. Trigger Full-Screen Blinking Alarm (5–10s, 7s default)
    if (report.overallScore >= 60) {
      triggerScreenAlarm('RED', report.overallScore, 7);
    } else if (report.overallScore >= 30) {
      triggerScreenAlarm('YELLOW', report.overallScore, 7);
    } else {
      triggerScreenAlarm('GREEN', report.overallScore, 7);
    }

    // 10. Display Analysis Card & Scroll
    analysisResultCard.style.display = 'flex';
    analysisResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function handleApkFile(file: File) {
    apkStatusNotice.style.display = 'block';
    apkStatusNotice.className = 'ocr-status-notice ocr-loading';
    apkStatusNotice.innerHTML = `⏳ Reading and analyzing APK package <code>${escapeHtml(file.name)}</code> (${(file.size / 1024).toFixed(1)} KB)...`;

    try {
      const buffer = await file.arrayBuffer();
      const report = await inspectApkBuffer(buffer, file.name);
      apkStatusNotice.className = 'ocr-status-notice ocr-success';
      apkStatusNotice.innerHTML = `✓ APK inspection complete for <code>${escapeHtml(report.appName || report.fileName)}</code>. Displaying SpotTheScam security report.`;
      await renderApkReport(report);
    } catch (err: any) {
      console.error('APK inspection failed:', err);
      apkStatusNotice.className = 'ocr-status-notice ocr-error';
      apkStatusNotice.innerHTML = `❌ Failed to inspect APK archive: ${escapeHtml(err.message || 'Invalid ZIP/APK structure')}`;
    }
  }

  async function handleDemoApk(type: 'MALICIOUS_SBI_TROJAN' | 'BENIGN_CALCULATOR') {
    apkStatusNotice.style.display = 'block';
    apkStatusNotice.className = 'ocr-status-notice ocr-loading';
    apkStatusNotice.innerHTML = `⏳ Generating and analyzing synthetic ${type === 'MALICIOUS_SBI_TROJAN' ? 'SBI Trojan APK' : 'Clean Calculator APK'} demo package...`;

    try {
      const buffer = await createDemoSampleApk(type);
      const fileName = type === 'MALICIOUS_SBI_TROJAN' ? 'SBI_YONO_Update_v2.apk' : 'Simple_Calculator_v1.apk';
      const report = await inspectApkBuffer(buffer, fileName);
      apkStatusNotice.className = 'ocr-status-notice ocr-success';
      apkStatusNotice.innerHTML = `✓ APK inspection complete for <code>${escapeHtml(report.appName)}</code>.`;
      await renderApkReport(report);
    } catch (err: any) {
      console.error('Demo APK failed:', err);
      apkStatusNotice.className = 'ocr-status-notice ocr-error';
      apkStatusNotice.innerHTML = `❌ Failed demo APK generation: ${escapeHtml(err.message)}`;
    }
  }

  btnBrowseApk?.addEventListener('click', () => apkFileInput?.click());
  apkFileInput?.addEventListener('change', () => {
    if (apkFileInput.files && apkFileInput.files[0]) {
      handleApkFile(apkFileInput.files[0]);
    }
  });

  apkDropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    apkDropZone.style.borderColor = 'var(--accent-red)';
  });
  apkDropZone?.addEventListener('dragleave', () => {
    apkDropZone.style.borderColor = 'var(--border-color)';
  });
  apkDropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    apkDropZone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer && e.dataTransfer.files[0]) {
      handleApkFile(e.dataTransfer.files[0]);
    }
  });

  btnApkDemoTrojan?.addEventListener('click', () => handleDemoApk('MALICIOUS_SBI_TROJAN'));
  btnApkDemoClean?.addEventListener('click', () => handleDemoApk('BENIGN_CALCULATOR'));

  // --------------------------------------------------------------------------
  // VirusTotal Multi-Engine File & Hash Inspector Flow
  // --------------------------------------------------------------------------
  function switchVtSubtab(tabName: 'DETECTION' | 'DETAILS' | 'BEHAVIOR' | 'PROTOCOL') {
    [vtTabDetection, vtTabDetails, vtTabBehavior, vtTabProtocol].forEach((btn) => btn?.classList.remove('active'));
    [vtPanelDetection, vtPanelDetails, vtPanelBehavior, vtPanelProtocol].forEach((panel) => {
      if (panel) panel.style.display = 'none';
    });

    if (tabName === 'DETECTION') {
      vtTabDetection?.classList.add('active');
      if (vtPanelDetection) vtPanelDetection.style.display = 'flex';
    } else if (tabName === 'DETAILS') {
      vtTabDetails?.classList.add('active');
      if (vtPanelDetails) vtPanelDetails.style.display = 'flex';
    } else if (tabName === 'BEHAVIOR') {
      vtTabBehavior?.classList.add('active');
      if (vtPanelBehavior) vtPanelBehavior.style.display = 'flex';
    } else if (tabName === 'PROTOCOL') {
      vtTabProtocol?.classList.add('active');
      if (vtPanelProtocol) vtPanelProtocol.style.display = 'flex';
    }
  }

  vtTabDetection?.addEventListener('click', () => switchVtSubtab('DETECTION'));
  vtTabDetails?.addEventListener('click', () => switchVtSubtab('DETAILS'));
  vtTabBehavior?.addEventListener('click', () => switchVtSubtab('BEHAVIOR'));
  vtTabProtocol?.addEventListener('click', () => switchVtSubtab('PROTOCOL'));

  async function renderVirusTotalReport(report: VirusTotalReport) {
    if (!vtInspectorCard) return;

    // 1. Hide other cards & reveal VT Inspector Card
    if (websiteInspectorCard) websiteInspectorCard.style.display = 'none';
    if (scamArchetypeBanner) scamArchetypeBanner.style.display = 'none';
    if (apkInspectorCard) apkInspectorCard.style.display = 'none';
    vtInspectorCard.style.display = 'flex';

    // 2. Populate Header & Detection Radial Meter
    vtFileNameText.textContent = report.fileName;
    vtFileMetaText.textContent = `${report.fileType} • ${(report.fileSizeBytes / 1024).toFixed(1)} KB • MIME: ${report.mimeType}`;
    vtRatioScore.textContent = `${report.stats.malicious}`;
    vtRatioTotal.textContent = `/ ${report.stats.totalEngines}`;

    vtRatioCircle.className = 'vt-ratio-circle';
    if (report.verdict === 'MALICIOUS') {
      vtRatioCircle.classList.add('danger');
      vtVerdictTitle.textContent = `${report.stats.detectionRatio} Security Vendors Flagged This File`;
      vtVerdictTitle.style.color = '#b91c1c';
      vtClassificationText.textContent = report.threatClassification || 'Malware Threat Detected';
    } else if (report.verdict === 'SUSPICIOUS') {
      vtRatioCircle.classList.add('warning');
      vtVerdictTitle.textContent = `${report.stats.detectionRatio} Security Vendors Flagged As Suspicious`;
      vtVerdictTitle.style.color = '#b45309';
      vtClassificationText.textContent = report.threatClassification || 'Potentially Unwanted Application (PUA)';
    } else {
      vtRatioCircle.classList.add('clean');
      vtVerdictTitle.textContent = `0 / ${report.stats.totalEngines} Security Vendors Flagged This File`;
      vtVerdictTitle.style.color = '#15803d';
      vtClassificationText.textContent = 'Clean Application — No Malicious Traits Found';
    }

    // 3. Populate Subtab 1: 72 Security Vendors Grid
    vtVendorSummaryCounts.textContent = `${report.stats.malicious} Malicious • ${report.stats.suspicious} Suspicious • ${report.stats.clean} Undetected`;
    vtVendorsGrid.innerHTML = report.vendorResults
      .map(
        (v) => `
        <div class="vt-vendor-item">
          <span class="vt-vendor-name" title="${escapeHtml(v.vendor)}">${escapeHtml(v.vendor)}</span>
          <span class="vt-vendor-status ${v.category}">
            ${
              v.category === 'malicious'
                ? `🟥 ${escapeHtml(v.result || 'Malicious')}`
                : v.category === 'suspicious'
                ? `🟨 ${escapeHtml(v.result || 'Suspicious')}`
                : '🟩 Clean'
            }
          </span>
        </div>
      `
      )
      .join('');

    // 4. Populate Subtab 2: Hashes, Magic, Entropy
    vtMd5Text.textContent = report.hashes.md5;
    vtSha1Text.textContent = report.hashes.sha1;
    vtSha256Text.textContent = report.hashes.sha256;
    vtFileTypeVal.textContent = report.fileType;
    vtMagicVal.textContent = `Magic Header: ${report.magicHeader}`;

    const entropyPercent = Math.min(100, (report.entropy.score / 8) * 100);
    vtEntropyFill.style.width = `${entropyPercent}%`;
    vtEntropyScoreVal.textContent = `${report.entropy.score.toFixed(2)} / 8.00 bits/byte`;
    vtEntropyRatingVal.textContent =
      report.entropy.rating === 'HIGH_PACKED'
        ? 'HIGH (Packed / Encrypted)'
        : report.entropy.rating === 'LOW'
        ? 'LOW (Uniform/Sparse)'
        : 'NORMAL (Unpacked)';
    vtEntropyRatingVal.style.color =
      report.entropy.rating === 'HIGH_PACKED'
        ? '#dc2626'
        : report.entropy.rating === 'LOW'
        ? '#2563eb'
        : '#16a34a';
    vtEntropyExplainVal.textContent = report.entropy.explanation;

    // 5. Populate Subtab 3: Behavior & Sandbox Indicators
    if (report.behaviorSignals.length > 0) {
      vtBehaviorSignalsList.innerHTML = report.behaviorSignals
        .map(
          (s) => `
          <div class="apk-perm-item ${s.severity === 'HIGH' ? 'critical' : 'dangerous'}">
            <div class="apk-perm-top">
              <span class="apk-perm-name">${escapeHtml(s.title)}</span>
              <span class="apk-perm-badge">${s.severity}</span>
            </div>
            <p class="apk-trojan-pattern">${escapeHtml(s.detail)}</p>
          </div>
        `
        )
        .join('');
    } else {
      vtBehaviorSignalsList.innerHTML = `
        <div style="font-size: 0.85rem; color: #16a34a; padding: 6px 0;">
          ✓ No dangerous behavioral API calls or process injection patterns detected.
        </div>
      `;
    }

    const networkCombined = [
      ...report.extractedStrings.urls.map((u) => `URL: ${u}`),
      ...report.extractedStrings.ips.map((ip) => `IP: ${ip}`),
    ];
    if (networkCombined.length > 0) {
      vtNetworkList.innerHTML = networkCombined.map((n) => `<div>🔗 ${escapeHtml(n)}</div>`).join('');
    } else {
      vtNetworkList.innerHTML = '<span style="color: #16a34a;">✓ No external C2 IP addresses or remote endpoints extracted.</span>';
    }

    // 6. Populate Subtab 4: Safety Protocol
    vtRecommendationsList.innerHTML = report.recommendations
      .map((r) => `<li>${escapeHtml(r)}</li>`)
      .join('');

    // Default to Detection subtab
    switchVtSubtab('DETECTION');

    // 7. Sync with Score Donut & History
    const calculatedScore = Math.min(100, Math.round((report.stats.malicious / report.stats.totalEngines) * 100));
    const fakeScanResult: ScanResult = {
      score: calculatedScore,
      rawScore: calculatedScore,
      riskLevel: report.riskLevel,
      headline:
        report.verdict === 'MALICIOUS'
          ? `VirusTotal: ${report.stats.detectionRatio} Vendors Flagged Malware`
          : report.verdict === 'SUSPICIOUS'
          ? `VirusTotal: ${report.stats.detectionRatio} Vendors Flagged Suspicious`
          : 'VirusTotal: 0/72 Clean Application',
      summary: `${report.stats.detectionRatio} security vendors flagged this file. Entropy: ${report.entropy.score} bits/byte (${report.entropy.rating}).`,
      advice: report.recommendations[0] || 'Inspect file before execution.',
      breakdown: report.vendorResults
        .filter((v) => v.category !== 'clean')
        .slice(0, 10)
        .map((v) => ({
          ruleId: v.vendor,
          label: `${v.vendor}: ${v.result || 'Threat Flag'}`,
          group: 'credential' as const,
          rawPoints: 10,
          awardedPoints: 10,
          category: 'VIRUSTOTAL_ENGINE',
          cappedByGroup: false,
          explanation: `Flagged by security vendor ${v.vendor}.`,
          evidence: [
            {
              ruleId: v.vendor,
              ruleLabel: v.vendor,
              group: 'credential' as const,
              matchedText: v.result || 'Threat',
              startIndex: 0,
              endIndex: (v.result || 'Threat').length,
              negated: false,
              category: 'VIRUSTOTAL_ENGINE',
            },
          ],
        })),
      unmatchedRules: [],
      allEvidence: [],
      activeEvidence: [],
      negatedEvidence: [],
      floorApplied: calculatedScore >= 60,
      metadata: {
        characterCount: report.fileSizeBytes,
        scannedAt: new Date().toISOString(),
        engineVersion: '2.4.0-virustotal',
        totalChecksRun: report.stats.totalEngines,
      },
    };

    currentResult = fakeScanResult;
    updateScoreWidgets(fakeScanResult);

    // Save to private local history
    HistoryService.saveScan(`[VirusTotal] ${report.fileName}`, fakeScanResult);

    // Trigger Blinking Alarm Overlay (7s)
    if (calculatedScore >= 60) {
      triggerScreenAlarm('RED', calculatedScore, 7);
    } else if (calculatedScore >= 30) {
      triggerScreenAlarm('YELLOW', calculatedScore, 7);
    } else {
      triggerScreenAlarm('GREEN', calculatedScore, 7);
    }

    // Reveal and scroll
    analysisResultCard.style.display = 'flex';
    analysisResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  async function handleVirusTotalFile(file: File) {
    vtStatusNotice.style.display = 'block';
    vtStatusNotice.className = 'ocr-status-notice ocr-loading';
    vtStatusNotice.innerHTML = `⏳ Inspecting file <code>${escapeHtml(file.name)}</code> (${(file.size / 1024).toFixed(1)} KB) across 72 antivirus engines...`;

    try {
      const buffer = await file.arrayBuffer();
      const report = await inspectFileVirusTotal(buffer, file.name);
      vtStatusNotice.className = 'ocr-status-notice ocr-success';
      vtStatusNotice.innerHTML = `✓ Multi-engine scan complete for <code>${escapeHtml(file.name)}</code> (${report.stats.detectionRatio} flagged).`;
      await renderVirusTotalReport(report);
    } catch (err: any) {
      console.error('VirusTotal inspection failed:', err);
      vtStatusNotice.className = 'ocr-status-notice ocr-error';
      vtStatusNotice.innerHTML = `❌ Failed file inspection: ${escapeHtml(err.message || 'File read error')}`;
    }
  }

  async function handleVirusTotalDemo(type: 'RANSOMWARE_PAYLOAD' | 'SUSPICIOUS_DROPPER' | 'CLEAN_TOOL') {
    vtStatusNotice.style.display = 'block';
    vtStatusNotice.className = 'ocr-status-notice ocr-loading';
    vtStatusNotice.innerHTML = '⏳ Generating and analyzing synthetic VirusTotal test payload...';

    try {
      const { buffer, fileName } = createVirusTotalDemoBuffer(type);
      const report = await inspectFileVirusTotal(buffer, fileName);
      vtStatusNotice.className = 'ocr-status-notice ocr-success';
      vtStatusNotice.innerHTML = `✓ Scan complete for <code>${escapeHtml(fileName)}</code> (${report.stats.detectionRatio} flagged).`;
      await renderVirusTotalReport(report);
    } catch (err: any) {
      console.error('VirusTotal demo failed:', err);
      vtStatusNotice.className = 'ocr-status-notice ocr-error';
      vtStatusNotice.innerHTML = `❌ Failed demo generation: ${escapeHtml(err.message)}`;
    }
  }

  async function handleVirusTotalHashSearch(hashQuery: string) {
    const q = hashQuery.trim().toLowerCase();
    if (!q) return;

    vtStatusNotice.style.display = 'block';
    vtStatusNotice.className = 'ocr-status-notice ocr-loading';
    vtStatusNotice.innerHTML = `🔍 Querying threat intelligence database for hash <code>${escapeHtml(q)}</code>...`;

    setTimeout(async () => {
      const known = KNOWN_THREAT_HASHES[q];
      if (known) {
        // Construct report from verified threat match
        const dummyBuffer = new TextEncoder().encode(`KNOWN_HASH_SAMPLE:${q}`).buffer as ArrayBuffer;
        const report = await inspectFileVirusTotal(dummyBuffer, `${known.name}.bin`);
        report.hashes.sha256 = q.length === 64 ? q : report.hashes.sha256;
        report.hashes.md5 = q.length === 32 ? q : report.hashes.md5;
        report.hashes.sha1 = q.length === 40 ? q : report.hashes.sha1;
        report.threatClassification = known.classification;
        report.stats.malicious = known.maliciousVendors;
        report.stats.clean = SECURITY_VENDORS.length - known.maliciousVendors;
        report.stats.detectionRatio = `${known.maliciousVendors} / ${SECURITY_VENDORS.length}`;
        report.verdict = 'MALICIOUS';
        report.riskLevel = 'HIGH';

        vtStatusNotice.className = 'ocr-status-notice ocr-success';
        vtStatusNotice.innerHTML = `✓ Threat match identified for hash: <strong>${escapeHtml(known.name)}</strong> (${known.maliciousVendors}/${SECURITY_VENDORS.length} vendors).`;
        await renderVirusTotalReport(report);
      } else {
        // Hash not in known database
        const dummyBuffer = new TextEncoder().encode(`HASH_INQUIRY:${q}`).buffer as ArrayBuffer;
        const report = await inspectFileVirusTotal(dummyBuffer, `HashSearch_${q.slice(0, 8)}.dat`);
        if (q.length === 64) report.hashes.sha256 = q;
        if (q.length === 32) report.hashes.md5 = q;
        if (q.length === 40) report.hashes.sha1 = q;

        vtStatusNotice.className = 'ocr-status-notice ocr-success';
        vtStatusNotice.innerHTML = `✓ Hash query evaluated: <code>${escapeHtml(q)}</code> (No verified public threat intelligence matches).`;
        await renderVirusTotalReport(report);
      }
    }, 400);
  }

  // Copy mini-buttons inside VirusTotal Details
  document.querySelectorAll('.vt-copy-mini-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      const targetId = (e.currentTarget as HTMLElement).getAttribute('data-copy');
      if (targetId) {
        const el = document.getElementById(targetId);
        if (el && el.textContent) {
          try {
            await navigator.clipboard.writeText(el.textContent);
            const orig = (e.currentTarget as HTMLElement).textContent;
            (e.currentTarget as HTMLElement).textContent = '✓';
            setTimeout(() => {
              (e.currentTarget as HTMLElement).textContent = orig;
            }, 1500);
          } catch {}
        }
      }
    });
  });

  btnBrowseVtFile?.addEventListener('click', () => vtFileInput?.click());
  vtFileInput?.addEventListener('change', () => {
    if (vtFileInput.files && vtFileInput.files[0]) {
      handleVirusTotalFile(vtFileInput.files[0]);
    }
  });

  vtDropZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    vtDropZone.style.borderColor = 'var(--accent-red)';
  });
  vtDropZone?.addEventListener('dragleave', () => {
    vtDropZone.style.borderColor = 'var(--border-color)';
  });
  vtDropZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    vtDropZone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer && e.dataTransfer.files[0]) {
      handleVirusTotalFile(e.dataTransfer.files[0]);
    }
  });

  btnSearchVtHash?.addEventListener('click', () => {
    handleVirusTotalHashSearch(vtHashSearchInput.value);
  });
  vtHashSearchInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleVirusTotalHashSearch(vtHashSearchInput.value);
    }
  });

  btnVtDemoRansomware?.addEventListener('click', () => handleVirusTotalDemo('RANSOMWARE_PAYLOAD'));
  btnVtDemoDropper?.addEventListener('click', () => handleVirusTotalDemo('SUSPICIOUS_DROPPER'));
  btnVtDemoClean?.addEventListener('click', () => handleVirusTotalDemo('CLEAN_TOOL'));

  textarea.addEventListener('paste', (e: ClipboardEvent) => {
    if (e.clipboardData && e.clipboardData.items) {
      for (const item of Array.from(e.clipboardData.items)) {
        if (item.type.startsWith('image/')) {
          e.preventDefault();
          const file = item.getAsFile();
          if (file) handleOcrFile(file);
          break;
        }
      }
    }
  });

  // --------------------------------------------------------------------------
  // Modals & Navigation
  // --------------------------------------------------------------------------
  btnSearchNav?.addEventListener('click', () => {
    dashboardMount.innerHTML = renderDashboardHtml();
    dashboardModal.classList.add('open');
  });
  closeDashboardModal?.addEventListener('click', () => dashboardModal.classList.remove('open'));

  menuHistory?.addEventListener('click', () => {
    renderHistoryList();
    historyModal.classList.add('open');
  });
  closeHistoryModal?.addEventListener('click', () => historyModal.classList.remove('open'));

  function openPricingModal() {
    const activeTier = localStorage.getItem('scam_spotter_active_tier') || 'FREE';
    pricingMount.innerHTML = renderPricingModal(activeTier);
    pricingModal.classList.add('open');
    attachPricingListeners();
  }

  function attachPricingListeners() {
    const tierButtons = pricingMount.querySelectorAll('.tier-btn');
    tierButtons.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const targetBtn = e.currentTarget as HTMLElement;
        const tierId = targetBtn.getAttribute('data-tier');

        if (tierId === 'FREE') {
          localStorage.setItem('scam_spotter_active_tier', 'FREE');
          openPricingModal();
        } else if (tierId === 'PREMIUM') {
          localStorage.setItem('scam_spotter_active_tier', 'PREMIUM');
          openPricingModal();
        } else if (tierId === 'ENTERPRISE') {
          window.location.href =
            'mailto:sales@scamspotter.org?subject=Scam%20Spotter%20FinTech%20API%20Inquiry';
        }
      });
    });
  }

  navPricing?.addEventListener('click', (e) => {
    e.preventDefault();
    openPricingModal();
  });
  btnViewPlansSidebar?.addEventListener('click', openPricingModal);
  closePricingModal?.addEventListener('click', () => pricingModal.classList.remove('open'));

  menuReport?.addEventListener('click', () => {
    reportSuccess.style.display = 'none';
    reportForm.reset();
    reportModal.classList.add('open');
  });
  closeReportModal?.addEventListener('click', () => reportModal.classList.remove('open'));

  menuLearn?.addEventListener('click', () => learnModal.classList.add('open'));
  navHowItWorks?.addEventListener('click', (e) => {
    e.preventDefault();
    learnModal.classList.add('open');
  });
  closeLearnModal?.addEventListener('click', () => learnModal.classList.remove('open'));

  // Close modals on backdrop click
  [dashboardModal, threatDbModal, evalModal, historyModal, pricingModal, reportModal, learnModal].forEach((m) => {
    m?.addEventListener('click', (e) => {
      if (e.target === m) m.classList.remove('open');
    });
  });

  // Global ESC key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      dismissScreenAlarm();
      [dashboardModal, threatDbModal, evalModal, historyModal, pricingModal, reportModal, learnModal].forEach((m) =>
        m?.classList.remove('open')
      );
    }
  });

  // --------------------------------------------------------------------------
  // History List Management
  // --------------------------------------------------------------------------
  function renderHistoryList() {
    const list = HistoryService.getHistory();
    if (list.length === 0) {
      historyListMount.innerHTML =
        '<p style="color: var(--text-muted); font-size: 0.9rem;">No saved scans found on this device.</p>';
      return;
    }

    historyListMount.innerHTML = list
      .map(
        (item) => `
      <div class="history-item-row" data-id="${item.id}" title="Click to load this message into scanner">
        <div style="flex-grow: 1; margin-right: 12px;">
          <div class="history-item-preview">${item.preview}</div>
          <div class="history-item-meta">
            ${new Date(item.createdAt).toLocaleDateString()} • 
            <span style="color: ${item.riskLevel === 'HIGH' ? 'var(--risk-high-text)' : item.riskLevel === 'MEDIUM' ? 'var(--risk-med-text)' : 'var(--risk-low-text)'}; font-weight: bold;">
              ${item.riskLevel} (${item.score}/100)
            </span>
            ${item.scamProfileName ? `• ${item.scamProfileName}` : ''}
          </div>
        </div>
        <div class="history-item-actions">
          <button class="btn-sidebar-cta btn-load-history" data-id="${item.id}" type="button" style="min-height: 28px; padding: 4px 10px; font-size: 0.75rem; margin-top: 0;">
            Load
          </button>
          <button class="btn-clear-history btn-delete-history" data-id="${item.id}" type="button" style="min-height: 28px; padding: 4px 8px; font-size: 0.75rem;">
            Delete
          </button>
        </div>
      </div>
    `
      )
      .join('');

    function loadItem(id: string | null) {
      if (!id) return;
      const item = list.find((x) => x.id === id);
      if (item) {
        switchTab('TEXT');
        textarea.value = item.preview;
        updateInputMetrics();
        historyModal.classList.remove('open');
        runAnalysis();
      }
    }

    document.querySelectorAll('.btn-load-history').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        loadItem((btn as HTMLElement).getAttribute('data-id'));
      });
    });

    document.querySelectorAll('.history-item-row').forEach((row) => {
      row.addEventListener('click', () => {
        loadItem((row as HTMLElement).getAttribute('data-id'));
      });
    });

    document.querySelectorAll('.btn-delete-history').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = (btn as HTMLElement).getAttribute('data-id');
        if (id) {
          HistoryService.deleteItem(id);
          renderHistoryList();
        }
      });
    });
  }

  btnClearHistory?.addEventListener('click', () => {
    if (confirm('Clear all stored scan history from this device?')) {
      HistoryService.clearHistory();
      renderHistoryList();
    }
  });

  // Report Form Submit
  reportForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const type = reportType.value as IndicatorType;
    const value = reportValue.value;
    const cat = reportCategory.value;

    ReportingService.submitReport(type, value, cat);
    reportSuccess.style.display = 'block';
    reportForm.reset();
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
