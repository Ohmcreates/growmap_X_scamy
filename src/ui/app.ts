import { generateSafeNextSteps } from '../engine/safeSteps.js';
import { analyzeMessage } from '../engine/scorer.js';
import { ScanResult } from '../engine/types.js';
import { AiAdvisorService } from '../services/aiAdvisor.js';
import { HistoryService } from '../services/history.js';
import { OcrService } from '../services/ocr.js';
import { IndicatorType, ReportingService } from '../services/reporting.js';
import { renderPricingModal, renderUnmatchedChecks } from './cards.js';
import { renderDashboardHtml } from './dashboard.js';
import { mergeHighlightSpans, renderHighlightedDom } from './highlighter.js';

export function initApp() {
  // Navigation & Theme Elements
  const btnThemeToggle = document.getElementById('btnThemeToggle') as HTMLButtonElement;
  const btnSearchNav = document.getElementById('btnSearchNav') as HTMLButtonElement;
  const navHowItWorks = document.getElementById('navHowItWorks') as HTMLAnchorElement;
  const navPricing = document.getElementById('navPricing') as HTMLAnchorElement;

  // Sidebar Elements
  const menuScanMessage = document.getElementById('menuScanMessage') as HTMLButtonElement;
  const menuScanLink = document.getElementById('menuScanLink') as HTMLButtonElement;
  const menuScanImage = document.getElementById('menuScanImage') as HTMLButtonElement;
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

  const dropZone = document.getElementById('dropZone') as HTMLElement;
  const btnBrowseOcr = document.getElementById('btnBrowseOcr') as HTMLButtonElement;
  const ocrFileInput = document.getElementById('ocrFileInput') as HTMLInputElement;

  // Example Buttons
  const btnExampleSbi = document.getElementById('btnExampleSbi') as HTMLButtonElement;
  const btnExampleDelivery = document.getElementById('btnExampleDelivery') as HTMLButtonElement;
  const btnExampleInvestment = document.getElementById('btnExampleInvestment') as HTMLButtonElement;
  const btnExampleJob = document.getElementById('btnExampleJob') as HTMLButtonElement;

  // Submit & Clear
  const btnAnalyze = document.getElementById('btnAnalyze') as HTMLButtonElement;
  const btnClearInput = document.getElementById('btnClearInput') as HTMLButtonElement;

  // Results Section
  const analysisResultCard = document.getElementById('analysisResultCard') as HTMLElement;
  const highlightedTextBox = document.getElementById('highlightedTextBox') as HTMLElement;
  const warningSignsMount = document.getElementById('warningSignsMount') as HTMLElement;
  const unmatchedMount = document.getElementById('unmatchedMount') as HTMLElement;
  const btnCopyHighlights = document.getElementById('btnCopyHighlights') as HTMLButtonElement;

  // AI Opinion
  const btnGetAiOpinion = document.getElementById('btnGetAiOpinion') as HTMLButtonElement;
  const aiOutputBox = document.getElementById('aiOutputBox') as HTMLElement;

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
  const historyModal = document.getElementById('historyModal') as HTMLElement;
  const pricingModal = document.getElementById('pricingModal') as HTMLElement;
  const reportModal = document.getElementById('reportModal') as HTMLElement;
  const learnModal = document.getElementById('learnModal') as HTMLElement;

  const closeDashboardModal = document.getElementById('closeDashboardModal') as HTMLButtonElement;
  const closeHistoryModal = document.getElementById('closeHistoryModal') as HTMLButtonElement;
  const closePricingModal = document.getElementById('closePricingModal') as HTMLButtonElement;
  const closeReportModal = document.getElementById('closeReportModal') as HTMLButtonElement;
  const closeLearnModal = document.getElementById('closeLearnModal') as HTMLButtonElement;

  const dashboardMount = document.getElementById('dashboardMount') as HTMLElement;
  const historyListMount = document.getElementById('historyListMount') as HTMLElement;
  const btnClearHistory = document.getElementById('btnClearHistory') as HTMLButtonElement;
  const pricingMount = document.getElementById('pricingMount') as HTMLElement;

  const reportForm = document.getElementById('reportForm') as HTMLFormElement;
  const reportType = document.getElementById('reportType') as HTMLSelectElement;
  const reportValue = document.getElementById('reportValue') as HTMLInputElement;
  const reportCategory = document.getElementById('reportCategory') as HTMLInputElement;
  const reportSuccess = document.getElementById('reportSuccess') as HTMLElement;

  let currentResult: ScanResult | null = null;
  let activeTab: 'TEXT' | 'LINK' | 'IMAGE' = 'TEXT';
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
  // Character Counter
  // --------------------------------------------------------------------------
  function updateCharCount() {
    const len = textarea.value.length;
    charCounter.textContent = `${len.toLocaleString()}/2000`;
  }

  textarea.addEventListener('input', () => {
    updateCharCount();
    inlineError.style.display = 'none';
  });

  // Cmd / Ctrl + Enter keyboard shortcut
  textarea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis();
    }
  });

  btnClearInput?.addEventListener('click', () => {
    textarea.value = '';
    urlInput.value = '';
    updateCharCount();
    inlineError.style.display = 'none';
    ocrStatusNotice.style.display = 'none';
    analysisResultCard.style.display = 'none';
    resetScoreWidgets();
  });

  // --------------------------------------------------------------------------
  // Example Buttons (Matching Mockup)
  // --------------------------------------------------------------------------
  btnExampleSbi?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'SBI ALERT: Your KYC is incomplete and your account will be blocked today. Update immediately at http://sbi-kyc-update.example/verify and share the OTP you receive to confirm.';
    updateCharCount();
    runAnalysis();
  });

  btnExampleDelivery?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Your package delivery has been held at customs due to unpaid duty of Rs 25. Pay immediately within 24 hours at http://india-post-parcel.xyz/pay to avoid cancellation.';
    updateCharCount();
    runAnalysis();
  });

  btnExampleInvestment?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Exclusive invitation: Guaranteed 300% returns in 7 days! Join VIP Telegram crypto trading group for daily profits. Transfer Rs 5,000 to initiate automated trading robot.';
    updateCharCount();
    runAnalysis();
  });

  btnExampleJob?.addEventListener('click', () => {
    switchTab('TEXT');
    textarea.value =
      'Part-time work from home opportunity! Earn Rs 3,500 daily just by liking YouTube videos and rating hotels on Telegram. Contact manager immediately to receive bonus.';
    updateCharCount();
    runAnalysis();
  });

  // --------------------------------------------------------------------------
  // FULL-SCREEN DYNAMIC BLINKING ALARM SYSTEM (5–10 SECONDS)
  // User Requirement:
  // "dont use red yellow and green in th website if the score is 60+ then therd will apper to blink in the website for 5 to 10 sc
  // if middle then yrllow woll be binking full screen for 5 to 10 sec
  // and saqme for the green"
  // --------------------------------------------------------------------------
  function triggerScreenAlarm(level: 'RED' | 'YELLOW' | 'GREEN', score: number, durationSeconds: number = 7) {
    // Clear any previous active alarms
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

    // 5. Update Analysis Result Card
    updateAnalysisCard(rawText, result);

    // 6. Smooth scroll to view results
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
    // Score Donut Arc Calculation
    // Circumference for r=40 is 2 * PI * 40 = 251.32
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

    // Safe Next Steps Stack
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
    // 1. Render Highlighted DOM
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

    // 2. Render Detected Warning Signs List (Matching Mockup Table)
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

    // 3. Unmatched Checks Drawer
    unmatchedMount.innerHTML = renderUnmatchedChecks(result.unmatchedRules);

    // Reset AI Box
    aiOutputBox.style.display = 'none';
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
      '🛡️ SCAM SPOTTER ANALYSIS',
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
  // AI Second Opinion Handler
  // --------------------------------------------------------------------------
  btnGetAiOpinion?.addEventListener('click', async () => {
    if (!currentResult || !textarea.value.trim()) return;

    btnGetAiOpinion.disabled = true;
    btnGetAiOpinion.textContent = '⏳ Analyzing...';
    aiOutputBox.style.display = 'block';
    aiOutputBox.innerHTML =
      '<p style="color: var(--text-muted);">Consulting contextual model with PII protection...</p>';

    try {
      const aiResult = await AiAdvisorService.getSecondOpinion(
        textarea.value.trim(),
        currentResult.score
      );

      const signalsList = aiResult.signals
        .map(
          (s) => `
        <li style="margin-bottom: 4px;">
          <code>"${s.phrase}"</code>: ${s.reason}
        </li>
      `
        )
        .join('');

      aiOutputBox.innerHTML = `
        <div style="font-size: 0.88rem; margin-bottom: 8px;">
          <strong>Contextual Reasoner:</strong> ${aiResult.summary}
        </div>
        ${
          aiResult.signals.length > 0
            ? `<ul style="margin-left: 20px; font-size: 0.82rem;">${signalsList}</ul>`
            : ''
        }
        <small style="color: var(--text-muted); display: block; margin-top: 6px;">${aiResult.note}</small>
      `;
    } catch {
      aiOutputBox.innerHTML =
        '<p style="color: var(--accent-red);">AI Advisory service unavailable. Deterministic rule analysis remains active.</p>';
    } finally {
      btnGetAiOpinion.disabled = false;
      btnGetAiOpinion.textContent = 'Consult AI';
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
      updateCharCount();

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

  // Clipboard paste support (Cmd+V screenshot directly into textarea)
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
  [dashboardModal, historyModal, pricingModal, reportModal, learnModal].forEach((m) => {
    m?.addEventListener('click', (e) => {
      if (e.target === m) m.classList.remove('open');
    });
  });

  // Global ESC key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      dismissScreenAlarm();
      [dashboardModal, historyModal, pricingModal, reportModal, learnModal].forEach((m) =>
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
        updateCharCount();
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
