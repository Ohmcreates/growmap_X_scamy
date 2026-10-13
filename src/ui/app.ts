import { analyzeMessage } from '../engine/scorer.js';
import { ScanResult } from '../engine/types.js';
import { AiAdvisorService } from '../services/aiAdvisor.js';
import { HistoryService } from '../services/history.js';
import { OcrService } from '../services/ocr.js';
import { IndicatorType, ReportingService } from '../services/reporting.js';
import {
  renderBreakdownCards,
  renderNextSteps,
  renderPricingModal,
  renderScoreGauge,
  renderUnmatchedChecks,
} from './cards.js';
import { renderDashboardHtml } from './dashboard.js';
import { mergeHighlightSpans, renderHighlightedDom } from './highlighter.js';

export function initApp() {
  const textarea = document.getElementById('messageInput') as HTMLTextAreaElement;
  const charCounter = document.getElementById('charCounter') as HTMLElement;
  const inlineError = document.getElementById('inlineError') as HTMLElement;
  const btnAnalyze = document.getElementById('btnAnalyze') as HTMLButtonElement;
  const btnClear = document.getElementById('btnClear') as HTMLButtonElement;

  const resultsContainer = document.getElementById('resultsContainer') as HTMLElement;
  const gaugeMount = document.getElementById('gaugeMount') as HTMLElement;
  const highlightedTextBox = document.getElementById('highlightedTextBox') as HTMLElement;
  const breakdownCardsMount = document.getElementById('breakdownCardsMount') as HTMLElement;
  const unmatchedMount = document.getElementById('unmatchedMount') as HTMLElement;
  const nextStepsMount = document.getElementById('nextStepsMount') as HTMLElement;

  const btnGetAiOpinion = document.getElementById('btnGetAiOpinion') as HTMLButtonElement;
  const aiOutputBox = document.getElementById('aiOutputBox') as HTMLElement;

  // Example Buttons
  const btnExampleSbi = document.getElementById('btnExampleSbi') as HTMLButtonElement;
  const btnExampleBank = document.getElementById('btnExampleBank') as HTMLButtonElement;
  const btnExampleDelivery = document.getElementById('btnExampleDelivery') as HTMLButtonElement;
  const btnExampleUpi = document.getElementById('btnExampleUpi') as HTMLButtonElement;

  // OCR Elements
  const btnOcrUpload = document.getElementById('btnOcrUpload') as HTMLButtonElement;
  const ocrFileInput = document.getElementById('ocrFileInput') as HTMLInputElement;
  const ocrStatusNotice = document.getElementById('ocrStatusNotice') as HTMLElement;

  // Modals
  const dashboardModal = document.getElementById('dashboardModal') as HTMLElement;
  const historyModal = document.getElementById('historyModal') as HTMLElement;
  const pricingModal = document.getElementById('pricingModal') as HTMLElement;
  const reportModal = document.getElementById('reportModal') as HTMLElement;

  const navDashboardBtn = document.getElementById('navDashboardBtn') as HTMLButtonElement;
  const navHistoryBtn = document.getElementById('navHistoryBtn') as HTMLButtonElement;
  const navPricingBtn = document.getElementById('navPricingBtn') as HTMLButtonElement;
  const navReportBtn = document.getElementById('navReportBtn') as HTMLButtonElement;

  const closeDashboardModal = document.getElementById('closeDashboardModal') as HTMLButtonElement;
  const closeHistoryModal = document.getElementById('closeHistoryModal') as HTMLButtonElement;
  const closePricingModal = document.getElementById('closePricingModal') as HTMLButtonElement;
  const closeReportModal = document.getElementById('closeReportModal') as HTMLButtonElement;

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

  // Character counter
  function updateCharCount() {
    const len = textarea.value.length;
    charCounter.textContent = `${len.toLocaleString()} / 5,000`;
    if (len >= 5000) {
      charCounter.classList.add('limit-exceeded');
    } else {
      charCounter.classList.remove('limit-exceeded');
    }
  }

  textarea.addEventListener('input', () => {
    updateCharCount();
    inlineError.style.display = 'none';
  });

  // Keyboard shortcut Ctrl/Cmd + Enter
  textarea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runAnalysis();
    }
  });

  btnClear.addEventListener('click', () => {
    textarea.value = '';
    updateCharCount();
    inlineError.style.display = 'none';
    resultsContainer.classList.remove('visible');
    aiOutputBox.style.display = 'none';
  });

  // Example button fixtures
  btnExampleSbi.addEventListener('click', () => {
    textarea.value =
      'Dear SBI customer, your KYC has expired. Your account will be BLOCKED today. Update immediately at http://sbi-kyc-update.xyz/login and share the OTP you receive to complete verification.';
    updateCharCount();
    runAnalysis();
  });

  btnExampleBank.addEventListener('click', () => {
    textarea.value =
      'Rs 500 debited from A/c XX1234 on 12-Oct. If not you, call the number on the back of your card. Never share OTP with anyone.';
    updateCharCount();
    runAnalysis();
  });

  btnExampleDelivery.addEventListener('click', () => {
    textarea.value =
      'Your delivery is held. Pay Rs 25 customs fee within 24 hours: bit.ly/xx12';
    updateCharCount();
    runAnalysis();
  });

  btnExampleUpi.addEventListener('click', () => {
    textarea.value =
      'Congratulations! You won Rs 25,000 cashback from PhonePe. Enter your UPI PIN immediately to receive the money in your account.';
    updateCharCount();
    runAnalysis();
  });

  btnAnalyze.addEventListener('click', runAnalysis);

  function runAnalysis() {
    const rawText = textarea.value.trim();
    if (!rawText) {
      inlineError.style.display = 'block';
      textarea.focus();
      return;
    }
    inlineError.style.display = 'none';

    // 1. Execute deterministic engine
    const result = analyzeMessage(rawText);
    currentResult = result;

    // 2. Persist to private history
    HistoryService.saveScan(rawText, result);

    // 3. Render Gauge & Headline
    gaugeMount.innerHTML = renderScoreGauge(result);

    // 4. Render Evidence Highlighter
    const mergedSpans = mergeHighlightSpans(rawText, result.activeEvidence);
    highlightedTextBox.innerHTML = '';
    const highlightedDom = renderHighlightedDom(
      rawText,
      mergedSpans,
      (ruleId) => {
        // Smooth scroll to explanation card and trigger focus pulse
        const targetCard = document.getElementById(`card-${ruleId}`);
        if (targetCard) {
          targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
          targetCard.classList.add('highlight-target');
          setTimeout(() => targetCard.classList.remove('highlight-target'), 2000);
        }
      }
    );
    highlightedTextBox.appendChild(highlightedDom);

    // 5. Render Explanation Cards
    breakdownCardsMount.innerHTML = renderBreakdownCards(result.breakdown);

    // 6. Render Unmatched Checks
    unmatchedMount.innerHTML = renderUnmatchedChecks(result.unmatchedRules);

    // 7. Render Safe Next Steps
    nextStepsMount.innerHTML = renderNextSteps(result);

    // Reset AI box
    aiOutputBox.style.display = 'none';

    // Show results
    resultsContainer.classList.add('visible');
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
  }

  // AI Second Opinion Handler
  btnGetAiOpinion.addEventListener('click', async () => {
    if (!currentResult || !textarea.value.trim()) return;

    btnGetAiOpinion.disabled = true;
    btnGetAiOpinion.textContent = '⏳ Analyzing Context...';
    aiOutputBox.style.display = 'block';
    aiOutputBox.innerHTML = '<p style="color: var(--text-muted);">Consulting contextual model with PII protection...</p>';

    try {
      const aiResult = await AiAdvisorService.getSecondOpinion(
        textarea.value.trim(),
        currentResult.score
      );

      const signalsList = aiResult.signals
        .map(
          (s) => `
        <li style="margin-bottom: 6px;">
          <code style="color: var(--accent-gold);">"${s.phrase}"</code>: ${s.reason}
        </li>
      `
        )
        .join('');

      aiOutputBox.innerHTML = `
        <div style="font-size: 0.95rem; margin-bottom: 12px; line-height: 1.6;">
          <strong>Contextual Assessment:</strong> ${aiResult.summary}
        </div>
        ${
          aiResult.signals.length > 0
            ? `
          <div style="font-size: 0.88rem; margin-bottom: 10px;">
            <span style="color: var(--text-muted);">Identified Linguistic Signals:</span>
            <ul style="margin-left: 20px; margin-top: 6px;">${signalsList}</ul>
          </div>
        `
            : ''
        }
        <p class="ai-disclaimer">${aiResult.note}</p>
      `;
    } catch {
      aiOutputBox.innerHTML =
        '<p style="color: var(--risk-med);">AI Advisory service is currently unavailable. Deterministic rule analysis remains fully active.</p>';
    } finally {
      btnGetAiOpinion.disabled = false;
      btnGetAiOpinion.textContent = '✨ Get AI Opinion';
    }
  });

  // Modals management
  navDashboardBtn.addEventListener('click', () => {
    dashboardMount.innerHTML = renderDashboardHtml();
    dashboardModal.classList.add('open');
  });
  closeDashboardModal.addEventListener('click', () => dashboardModal.classList.remove('open'));

  navHistoryBtn.addEventListener('click', () => {
    renderHistoryList();
    historyModal.classList.add('open');
  });
  closeHistoryModal.addEventListener('click', () => historyModal.classList.remove('open'));

  navPricingBtn.addEventListener('click', () => {
    pricingMount.innerHTML = renderPricingModal();
    pricingModal.classList.add('open');
  });
  closePricingModal.addEventListener('click', () => pricingModal.classList.remove('open'));

  navReportBtn.addEventListener('click', () => {
    reportSuccess.style.display = 'none';
    reportForm.reset();
    reportModal.classList.add('open');
  });
  closeReportModal.addEventListener('click', () => reportModal.classList.remove('open'));

  // Close modals on background backdrop click
  [dashboardModal, historyModal, pricingModal, reportModal].forEach((modal) => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('open');
    });
  });

  // OCR Processing flow
  async function handleOcrImageFile(file: File | Blob) {
    ocrStatusNotice.style.display = 'block';
    ocrStatusNotice.className = 'ocr-status-notice ocr-loading';
    ocrStatusNotice.innerHTML = '⏳ Preprocessing screenshot and extracting text...';

    try {
      const ocrResult = await OcrService.extractTextFromImage(file, (progress, status) => {
        ocrStatusNotice.innerHTML = `⏳ ${status} (${progress}%)`;
      });

      textarea.value = ocrResult.text;
      updateCharCount();

      if (ocrResult.lowConfidence && ocrResult.notice) {
        ocrStatusNotice.className = 'ocr-status-notice ocr-warning';
        ocrStatusNotice.innerHTML = `⚠️ ${ocrResult.notice}`;
      } else {
        ocrStatusNotice.className = 'ocr-status-notice ocr-success';
        ocrStatusNotice.innerHTML = `✓ Text extracted (${Math.round(ocrResult.confidence)}% confidence). Please review and click Analyze.`;
      }
    } catch (err) {
      console.error('OCR failed:', err);
      ocrStatusNotice.className = 'ocr-status-notice ocr-error';
      ocrStatusNotice.innerHTML = '❌ Could not extract text from this image. Please paste text directly.';
    }
  }

  btnOcrUpload.addEventListener('click', () => {
    ocrFileInput.click();
  });

  ocrFileInput.addEventListener('change', () => {
    if (ocrFileInput.files && ocrFileInput.files[0]) {
      handleOcrImageFile(ocrFileInput.files[0]);
    }
  });

  // Also support pasting images directly from clipboard (e.g. Cmd+V screenshot)
  textarea.addEventListener('paste', (e: ClipboardEvent) => {
    if (e.clipboardData && e.clipboardData.items) {
      for (const item of Array.from(e.clipboardData.items)) {
        if (item.type.startsWith('image/')) {
          e.preventDefault();
          const file = item.getAsFile();
          if (file) {
            handleOcrImageFile(file);
          }
          break;
        }
      }
    }
  });

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
      <div class="history-item-row" data-id="${item.id}">
        <div>
          <div class="history-item-preview">${item.preview}</div>
          <div class="history-item-meta">
            ${new Date(item.createdAt).toLocaleDateString()} ${new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • 
            <span style="color: ${item.riskLevel === 'HIGH' ? 'var(--risk-high)' : item.riskLevel === 'MEDIUM' ? 'var(--risk-med)' : 'var(--risk-low)'}; font-weight: bold;">
              ${item.riskLevel} (${item.score}/100)
            </span>
            ${item.scamProfileName ? `• ${item.scamProfileName}` : ''}
          </div>
        </div>
        <button class="btn-secondary btn-delete-history" data-id="${item.id}" style="min-height: 32px; padding: 4px 8px; font-size: 0.75rem;">
          Delete
        </button>
      </div>
    `
      )
      .join('');

    // Attach delete listeners
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

  btnClearHistory.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all scan history from this device?')) {
      HistoryService.clearHistory();
      renderHistoryList();
    }
  });

  // Report submission handler
  reportForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const type = reportType.value as IndicatorType;
    const value = reportValue.value;
    const cat = reportCategory.value;

    ReportingService.submitReport(type, value, cat);
    reportSuccess.style.display = 'block';
    reportForm.reset();
  });
}
