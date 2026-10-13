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
import { predictPhishingMlAsync, MlModelAssessment } from '../engine/phishingMl.js';
import { mergeHighlightSpans, renderHighlightedDom } from './highlighter.js';
import { GeminiService } from '../services/geminiService.js';

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

  const panelTextMessage = document.getElementById('panelTextMessage') as HTMLElement;
  const panelScanLink = document.getElementById('panelScanLink') as HTMLElement;
  const panelUploadImage = document.getElementById('panelUploadImage') as HTMLElement;

  const textarea = document.getElementById('messageInput') as HTMLTextAreaElement;
  const urlInput = document.getElementById('urlInput') as HTMLInputElement;
  const charCounter = document.getElementById('charCounter') as HTMLElement;
  const inlineError = document.getElementById('inlineError') as HTMLElement;
  const ocrStatusNotice = document.getElementById('ocrStatusNotice') as HTMLElement;
  const langScriptPill = document.getElementById('langScriptPill') as HTMLElement;

  const dropZone = document.getElementById('dropZone') as HTMLElement;
  const btnBrowseOcr = document.getElementById('btnBrowseOcr') as HTMLButtonElement;
  const ocrFileInput = document.getElementById('ocrFileInput') as HTMLInputElement;

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

  // ML Phishing Forensics Elements
  const webMlSection = document.getElementById('webMlSection') as HTMLElement;
  const webMlModelName = document.getElementById('webMlModelName') as HTMLElement;
  const webMlSourceBadge = document.getElementById('webMlSourceBadge') as HTMLElement;
  const webMlProbability = document.getElementById('webMlProbability') as HTMLElement;
  const webMlVerdictPill = document.getElementById('webMlVerdictPill') as HTMLElement;
  const webMlFeaturesGrid = document.getElementById('webMlFeaturesGrid') as HTMLElement;

  const btnUrlSbiPhish = document.getElementById('btnUrlSbiPhish') as HTMLButtonElement;
  const btnUrlChallanPhish = document.getElementById('btnUrlChallanPhish') as HTMLButtonElement;
  const btnUrlIpPhish = document.getElementById('btnUrlIpPhish') as HTMLButtonElement;
  const btnUrlShortener = document.getElementById('btnUrlShortener') as HTMLButtonElement;
  const btnUrlOfficialSbi = document.getElementById('btnUrlOfficialSbi') as HTMLButtonElement;

  // Google Gemini AI Cybersecurity Advisory Elements (Purpose 1 & 2)
  const geminiAdvisoryCard = document.getElementById('geminiAdvisoryCard') as HTMLElement;
  const geminiModelBadge = document.getElementById('geminiModelBadge') as HTMLElement;
  const geminiThreatBadge = document.getElementById('geminiThreatBadge') as HTMLElement;
  const geminiVerdictBadge = document.getElementById('geminiVerdictBadge') as HTMLElement;
  const geminiTargetedBrand = document.getElementById('geminiTargetedBrand') as HTMLElement;
  const geminiCategory = document.getElementById('geminiCategory') as HTMLElement;
  const geminiConfidenceScore = document.getElementById('geminiConfidenceScore') as HTMLElement;
  const geminiRiskIndicatorsList = document.getElementById('geminiRiskIndicatorsList') as HTMLElement;
  const geminiUserGuidanceText = document.getElementById('geminiUserGuidanceText') as HTMLElement;


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
  let activeTab: 'TEXT' | 'LINK' | 'IMAGE' | 'APK' | 'VT' | 'NCII' = 'TEXT';
  let alarmInterval: number | null = null;
  let alarmTimeout: number | null = null;

  // --------------------------------------------------------------------------
  // Theme Toggle (Light / Dark)
  // --------------------------------------------------------------------------
  const savedTheme = localStorage.getItem('scamy_theme');
  if (savedTheme === 'dark') {
    document.body.classList.add('theme-dark');
    if (btnThemeToggle) btnThemeToggle.textContent = '🌙';
  }

  btnThemeToggle?.addEventListener('click', () => {
    document.body.classList.toggle('theme-dark');
    const isDark = document.body.classList.contains('theme-dark');
    btnThemeToggle.textContent = isDark ? '🌙' : '☀️';
    try {
      localStorage.setItem('scamy_theme', isDark ? 'dark' : 'light');
    } catch {}
  });

  // --------------------------------------------------------------------------
  // Tab Switching
  // --------------------------------------------------------------------------
  function switchTab(tab: 'TEXT' | 'LINK' | 'IMAGE') {
    activeTab = tab;

    [tabTextMessage, tabScanLink, tabUploadImage].forEach((t) => t?.classList.remove('active'));
    [panelTextMessage, panelScanLink, panelUploadImage].forEach((p) => {
      if (p) p.style.display = 'none';
    });

    [menuScanMessage, menuScanLink, menuScanImage].forEach((m) => m?.classList.remove('active'));

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
    }
  }

  tabTextMessage?.addEventListener('click', () => switchTab('TEXT'));
  tabScanLink?.addEventListener('click', () => switchTab('LINK'));
  tabUploadImage?.addEventListener('click', () => switchTab('IMAGE'));

  menuScanMessage?.addEventListener('click', () => switchTab('TEXT'));
  menuScanLink?.addEventListener('click', () => switchTab('LINK'));
  menuScanImage?.addEventListener('click', () => switchTab('IMAGE'));

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
    if (websiteInspectorCard) websiteInspectorCard.style.display = 'none';
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
    urlInput.value = 'https://mparivahan.redirectme.net/6/RTO.MoRTH';
    runAnalysis();
  });

  btnUrlIpPhish?.addEventListener('click', () => {
    switchTab('LINK');
    urlInput.value = 'http://192.168.1.1/secure-bank-login-verify/account.html';
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
    if (result.score >= 45) {
      triggerScreenAlarm('RED', result.score, 7);
    } else if (result.score >= 21) {
      triggerScreenAlarm('YELLOW', result.score, 7);
    } else {
      triggerScreenAlarm('GREEN', result.score, 7);
    }

    // 4. Update Right Column Widgets
    updateScoreWidgets(result);

    // 5. Update Analysis Result Card & Specialized Classifiers
    updateAnalysisCard(rawText, result);

    // 5.1 Trigger Google Gemini AI Cybersecurity Advisory (Purpose 1 & 2: Message & URL Checker)
    triggerGeminiAdvisory(rawText);

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
    if (result.scamProfile && result.score > 0) {
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

      // Heuristic Verification Engine (15 Concrete Rules)
      if (webResult.heuristics) {
        renderHeuristicsAssessment(webResult.heuristics);
      }

      // Machine Learning Phishing Forensics (Random Forest 10-Feature Vector)
      if (webResult.mlAssessment) {
        renderMlAssessment(webResult.mlAssessment);

        predictPhishingMlAsync(rawText)
          .then((asyncMl) => {
            renderMlAssessment(asyncMl);
          })
          .catch(() => {});
      }
    } else if (websiteInspectorCard) {
      websiteInspectorCard.style.display = 'none';
    }

    function renderHeuristicsAssessment(h: any) {
      const webHeuristicsSection = document.getElementById('webHeuristicsSection') as HTMLElement;
      const webHeuristicsScoreBadge = document.getElementById('webHeuristicsScoreBadge') as HTMLElement;
      const webHeuristicsRiskPill = document.getElementById('webHeuristicsRiskPill') as HTMLElement;
      const webHeuristicsRulesCount = document.getElementById('webHeuristicsRulesCount') as HTMLElement;
      const webHeuristicsRulesList = document.getElementById('webHeuristicsRulesList') as HTMLElement;
      const thresholdSegments = document.querySelectorAll('.web-heuristics-threshold-bar .threshold-segment');

      if (!webHeuristicsSection || !webHeuristicsRulesList) return;
      webHeuristicsSection.style.display = 'flex';

      if (webHeuristicsScoreBadge) {
        webHeuristicsScoreBadge.textContent = `Threat Score: ${h.totalScore}/100`;
      }

      // Threshold Active Segments: 0-25 Low, 26-55 Medium, 56+ High
      thresholdSegments.forEach((seg) => seg.classList.remove('active'));
      if (h.riskCode === 'HIGH') {
        const seg = document.querySelector('.web-heuristics-threshold-bar .seg-high');
        if (seg) seg.classList.add('active');
      } else if (h.riskCode === 'MEDIUM') {
        const seg = document.querySelector('.web-heuristics-threshold-bar .seg-med');
        if (seg) seg.classList.add('active');
      } else {
        const seg = document.querySelector('.web-heuristics-threshold-bar .seg-low');
        if (seg) seg.classList.add('active');
      }

      if (webHeuristicsRiskPill) {
        if (h.riskCode === 'HIGH') {
          webHeuristicsRiskPill.className = 'web-heuristics-risk-pill high';
          webHeuristicsRiskPill.textContent = '56+: High Risk (Likely Phishing / Scam)';
        } else if (h.riskCode === 'MEDIUM') {
          webHeuristicsRiskPill.className = 'web-heuristics-risk-pill medium';
          webHeuristicsRiskPill.textContent = '26–55: Medium Risk (Suspicious)';
        } else {
          webHeuristicsRiskPill.className = 'web-heuristics-risk-pill low';
          webHeuristicsRiskPill.textContent = '0–25: Low Risk (Likely Safe)';
        }
      }

      if (webHeuristicsRulesCount) {
        webHeuristicsRulesCount.textContent = `${h.firedRules.length} Rule${h.firedRules.length === 1 ? '' : 's'} Fired`;
      }

      if (h.firedRules.length === 0) {
        webHeuristicsRulesList.innerHTML = `
          <div style="font-size: 0.82rem; color: #16a34a; padding: 10px 12px; background: rgba(34, 197, 94, 0.08); border-radius: var(--radius-sm); border: 1px dashed rgba(34, 197, 94, 0.3);">
            ✓ 0 of 15 heuristic triggers activated. URL syntax, domain registration structure, and credentials comply with baseline safety rules.
          </div>
        `;
      } else {
        webHeuristicsRulesList.innerHTML = h.firedRules
          .map(
            (r: any) => `
          <div class="heuristic-rule-item">
            <div class="rule-left-cluster">
              <div class="rule-header-tags">
                <span class="rule-code-badge">${r.code}</span>
                <span class="rule-category-pill ${String(r.category).toLowerCase()}">${r.category}</span>
                <span class="rule-title-text">${escapeHtml(r.title)}</span>
              </div>
              <p class="rule-desc-text">${escapeHtml(r.detail)}</p>
              <span class="rule-evidence-tag">Evidence: ${escapeHtml(r.evidence)}</span>
            </div>
            <span class="rule-points-badge">+${r.points}</span>
          </div>
        `
          )
          .join('');
      }
    }

    function renderMlAssessment(ml: MlModelAssessment) {
      if (!webMlSection || !webMlFeaturesGrid) return;
      webMlSection.style.display = 'flex';

      if (webMlModelName) {
        webMlModelName.textContent = ml.modelName || 'RandomForestClassifier (100 Trees)';
      }

      if (webMlProbability) {
        webMlProbability.textContent = `ML Phishing Risk: ${ml.phishingProbability}%`;
      }

      if (webMlSourceBadge) {
        webMlSourceBadge.textContent =
          ml.engineSource === 'PYTHON_FLASK_API'
            ? 'Flask ML Server (phishing_model.pkl)'
            : 'Client ML Engine (10-Feature)';
      }

      if (webMlVerdictPill) {
        if (ml.isPhishing) {
          webMlVerdictPill.className = 'web-ml-verdict-pill danger';
          webMlVerdictPill.textContent = `🚨 PHISHING (${ml.confidenceScore}% Confidence)`;
        } else {
          webMlVerdictPill.className = 'web-ml-verdict-pill success';
          webMlVerdictPill.textContent = `🛡️ LEGITIMATE (${ml.confidenceScore}% Confidence)`;
        }
      }

      const featureDefs = [
        { key: 'url_length', label: 'URL Length' },
        { key: 'dot_count', label: 'Dot Count' },
        { key: 'hyphen_count', label: 'Hyphen Count' },
        { key: 'at_symbol', label: '@ Redirection' },
        { key: 'double_slash_redirect', label: '// Redirect' },
        { key: 'has_ip_address', label: 'Raw IP Host' },
        { key: 'subdomain_count', label: 'Subdomains' },
        { key: 'domain_length', label: 'Domain Length' },
        { key: 'https_flag', label: 'HTTPS Scheme' },
        { key: 'suspicious_words', label: 'Suspicious Keywords' },
      ];

      webMlFeaturesGrid.innerHTML = featureDefs
        .map((item) => {
          const val = (ml.featureVector as any)[item.key];
          let valClass = '';
          if (['has_ip_address', 'double_slash_redirect', 'suspicious_words', 'at_symbol'].includes(item.key) && val > 0) {
            valClass = 'risk';
          } else if (item.key === 'https_flag' && val === 1) {
            valClass = 'safe';
          } else if (item.key === 'hyphen_count' && val >= 2) {
            valClass = 'risk';
          }
          return `
            <div class="web-ml-feature-cell">
              <span class="f-name">${item.label}</span>
              <span class="f-val ${valClass}">${val !== undefined ? val : '-'}</span>
            </div>
          `;
        })
        .join('');
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

  async function triggerGeminiAdvisory(rawText: string) {
    if (!geminiAdvisoryCard) return;

    geminiAdvisoryCard.style.display = 'flex';
    if (geminiModelBadge) geminiModelBadge.textContent = 'Gemini 3.5 Flash';
    if (geminiThreatBadge) {
      geminiThreatBadge.className = 'gemini-threat-badge medium';
      geminiThreatBadge.textContent = 'ANALYZING...';
    }
    if (geminiVerdictBadge) {
      geminiVerdictBadge.className = 'gemini-verdict-badge';
      geminiVerdictBadge.textContent = 'EVALUATING';
    }
    if (geminiTargetedBrand) geminiTargetedBrand.textContent = 'Scanning...';
    if (geminiCategory) geminiCategory.textContent = 'Classifying...';
    if (geminiConfidenceScore) geminiConfidenceScore.textContent = '...';
    if (geminiRiskIndicatorsList) {
      geminiRiskIndicatorsList.innerHTML = '<li>⏳ Consulting Google Gemini Expert Cybersecurity Engine...</li>';
    }
    if (geminiUserGuidanceText) {
      geminiUserGuidanceText.textContent = 'Verifying against social engineering & URL deception checklist...';
    }

    try {
      const g = await GeminiService.analyzeMessageOrUrl(rawText);

      if (geminiModelBadge) geminiModelBadge.textContent = g.sourceModel || 'Gemini 3.5 Flash';

      const vLower = (g.verdict || 'SAFE').toLowerCase();
      if (geminiVerdictBadge) {
        geminiVerdictBadge.className = `gemini-verdict-badge ${vLower === 'scam' ? 'scam' : vLower === 'suspicious' ? 'suspicious' : 'safe'}`;
        geminiVerdictBadge.textContent = g.verdict;
      }

      const tLower = (g.threat_level || 'LOW').toLowerCase();
      if (geminiThreatBadge) {
        geminiThreatBadge.className = `gemini-threat-badge ${tLower}`;
        geminiThreatBadge.textContent = `${g.threat_level} THREAT`;
      }

      if (geminiTargetedBrand) geminiTargetedBrand.textContent = g.targeted_brand_or_entity || 'None';
      if (geminiCategory) geminiCategory.textContent = g.scam_category || 'Legitimate/None';
      if (geminiConfidenceScore) geminiConfidenceScore.textContent = `${g.confidence_score}% Confidence`;

      if (geminiRiskIndicatorsList) {
        if (g.risk_indicators && g.risk_indicators.length > 0) {
          geminiRiskIndicatorsList.innerHTML = g.risk_indicators
            .map((ind) => `<li>⚠️ ${escapeHtml(ind)}</li>`)
            .join('');
        } else {
          geminiRiskIndicatorsList.innerHTML = '<li>✓ No explicit red flags detected by cybersecurity models.</li>';
        }
      }

      if (geminiUserGuidanceText) {
        geminiUserGuidanceText.textContent = g.user_guidance || 'Verify all unexpected correspondence independently.';
      }

      // Escalate full-screen alarm if Gemini confirms scam
      if (g.verdict === 'SCAM' || g.threat_level === 'CRITICAL' || g.threat_level === 'HIGH') {
        triggerScreenAlarm('RED', Math.max(g.confidence_score, 85), 7);
      }
    } catch (err) {
      console.warn('Gemini Advisory error:', err);
      if (geminiModelBadge) geminiModelBadge.textContent = 'Local Failover';
      if (geminiVerdictBadge) {
        geminiVerdictBadge.className = 'gemini-verdict-badge safe';
        geminiVerdictBadge.textContent = 'LOCAL PASS';
      }
      if (geminiThreatBadge) geminiThreatBadge.textContent = 'LOCAL CHECK';
      if (geminiRiskIndicatorsList) {
        geminiRiskIndicatorsList.innerHTML = '<li>ℹ️ Local deterministic engine applied.</li>';
      }
    }
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
  function readBlobAsBase64(blob: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  async function handleOcrFile(file: File | Blob) {
    ocrStatusNotice.style.display = 'block';
    ocrStatusNotice.className = 'ocr-status-notice ocr-loading';
    ocrStatusNotice.innerHTML = '✨ Running Google Gemini Multimodal Vision & Photo OCR...';

    // Purpose 3: Multimodal Vision OCR with Gemini
    try {
      const base64Data = await readBlobAsBase64(file);
      const mime = file.type || 'image/jpeg';
      const gOcr = await GeminiService.performPhotoOcr(base64Data, mime);

      if (gOcr && gOcr.extractedText && gOcr.extractedText.trim().length > 0) {
        switchTab('TEXT');
        textarea.value = gOcr.extractedText;
        updateInputMetrics();

        const docType = gOcr.documentType || 'Screenshot / Photo';
        const urlsCount = (gOcr.detectedUrls || []).length;
        const phonesCount = (gOcr.detectedPhoneNumbers || []).length;
        const fraudAlert = gOcr.initialFraudAssessment?.isSuspicious
          ? ` ⚠️ Initial Forensic Flag: ${escapeHtml(gOcr.initialFraudAssessment.reason)}`
          : '';

        ocrStatusNotice.className = 'ocr-status-notice ocr-success';
        ocrStatusNotice.innerHTML = `✨ <strong>Google Gemini Photo OCR (${gOcr.confidence}%):</strong> Extracted text from ${escapeHtml(docType)}. ${urlsCount ? `${urlsCount} URL(s) detected. ` : ''}${phonesCount ? `${phonesCount} Phone(s) detected.` : ''}${fraudAlert} Running deep fraud analysis...`;

        runAnalysis();
        return;
      }
    } catch (gErr) {
      console.warn('Gemini Photo OCR fell back to local engine:', gErr);
    }

    // Local fallback using Tesseract.js & jsQR
    ocrStatusNotice.className = 'ocr-status-notice ocr-loading';
    ocrStatusNotice.innerHTML = '⏳ Processing with client-side OCR engine...';

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
      handleOcrFile(ocrFileInput.files[0]);
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
      handleOcrFile(e.dataTransfer.files[0]);
    }
  });

  textarea.addEventListener('paste', (e: ClipboardEvent) => {
    if (e.clipboardData && e.clipboardData.items) {
      for (const item of Array.from(e.clipboardData.items)) {
        if (item.type.startsWith('image/')) {
          e.preventDefault();
          const file = item.getAsFile();
          if (file) {
            handleOcrFile(file);
          }
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
