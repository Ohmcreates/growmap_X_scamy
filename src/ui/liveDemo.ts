/**
 * Scam Spotter — Live Product Demonstration Component
 *
 * Uses the real underlying Scam Spotter deterministic scoring engine (analyzeMessage)
 * and safety advisor (generateSafeNextSteps) to demonstrate authentic fraud analysis
 * on the fictional SBI KYC scam and custom user inputs.
 */

import { ActionStep, generateSafeNextSteps } from '../engine/safeSteps.js';
import { analyzeMessage } from '../engine/scorer.js';
import { ScanResult } from '../engine/types.js';
import { router } from './router.js';

export const DEMO_SAMPLES = {
  sbiKyc:
    'Dear SBI Customer, your account will be blocked today due to incomplete KYC. Update immediately at http://sbi-kyc-update.xyz and enter OTP to verify.',
  indiaPost:
    'India Post: Your package delivery failed due to unpaid customs fee of Rs 5. Pay within 12 hours to reschedule delivery here: http://bit.ly/indpst-fee',
  electricity:
    'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call electricity officer immediately at 9876543210.',
  legitimate:
    'SBI: Rs 1,500.00 debited from A/C ...1234 on 12-Oct-26 at ATM. Avail Bal: Rs 42,300. If not done by you, forward SMS to 9223008333.',
};

export class LiveDemoController {
  private inputEl: HTMLTextAreaElement | null = null;
  private btnAnalyze: HTMLButtonElement | null = null;
  private chipSbi: HTMLElement | null = null;
  private chipPost: HTMLElement | null = null;
  private chipElec: HTMLElement | null = null;
  private chipSafe: HTMLElement | null = null;

  // Output elements
  private highlightedTextMount: HTMLElement | null = null;
  private scoreValueEl: HTMLElement | null = null;
  private riskBadgeEl: HTMLElement | null = null;
  private breakdownListMount: HTMLElement | null = null;
  private safeStepsMount: HTMLElement | null = null;
  private btnOpenInWorkspace: HTMLElement | null = null;

  public init() {
    this.inputEl = document.getElementById('demoMessageInput') as HTMLTextAreaElement | null;
    this.btnAnalyze = document.getElementById('btnDemoAnalyze') as HTMLButtonElement | null;
    this.chipSbi = document.getElementById('chipDemoSbi');
    this.chipPost = document.getElementById('chipDemoPost');
    this.chipElec = document.getElementById('chipDemoElec');
    this.chipSafe = document.getElementById('chipDemoSafe');

    this.highlightedTextMount = document.getElementById('demoHighlightedTextMount');
    this.scoreValueEl = document.getElementById('demoScoreValue');
    this.riskBadgeEl = document.getElementById('demoRiskBadge');
    this.breakdownListMount = document.getElementById('demoBreakdownListMount');
    this.safeStepsMount = document.getElementById('demoSafeStepsMount');
    this.btnOpenInWorkspace = document.getElementById('btnDemoOpenInWorkspace');

    if (!this.inputEl || !this.btnAnalyze) return;

    // Default prefill: Fictional SBI KYC Scam
    if (!this.inputEl.value) {
      this.inputEl.value = DEMO_SAMPLES.sbiKyc;
    }

    this.btnAnalyze.addEventListener('click', () => {
      this.runAnalysis(this.inputEl?.value || '');
    });

    this.chipSbi?.addEventListener('click', () => {
      if (this.inputEl) this.inputEl.value = DEMO_SAMPLES.sbiKyc;
      this.setActiveChip(this.chipSbi);
      this.runAnalysis(DEMO_SAMPLES.sbiKyc);
    });

    this.chipPost?.addEventListener('click', () => {
      if (this.inputEl) this.inputEl.value = DEMO_SAMPLES.indiaPost;
      this.setActiveChip(this.chipPost);
      this.runAnalysis(DEMO_SAMPLES.indiaPost);
    });

    this.chipElec?.addEventListener('click', () => {
      if (this.inputEl) this.inputEl.value = DEMO_SAMPLES.electricity;
      this.setActiveChip(this.chipElec);
      this.runAnalysis(DEMO_SAMPLES.electricity);
    });

    this.chipSafe?.addEventListener('click', () => {
      if (this.inputEl) this.inputEl.value = DEMO_SAMPLES.legitimate;
      this.setActiveChip(this.chipSafe);
      this.runAnalysis(DEMO_SAMPLES.legitimate);
    });

    this.btnOpenInWorkspace?.addEventListener('click', () => {
      const currentText = this.inputEl?.value || DEMO_SAMPLES.sbiKyc;
      const mainTextarea = document.getElementById('messageInput') as HTMLTextAreaElement | null;
      if (mainTextarea) {
        mainTextarea.value = currentText;
        mainTextarea.dispatchEvent(new Event('input', { bubbles: true }));
      }
      router.navigate('workspace');
    });

    // Run initial analysis on page load
    this.runAnalysis(this.inputEl.value);
  }

  private setActiveChip(activeEl: HTMLElement | null) {
    [this.chipSbi, this.chipPost, this.chipElec, this.chipSafe].forEach((chip) => {
      chip?.classList.remove('active');
    });
    activeEl?.classList.add('active');
  }

  public runAnalysis(text: string) {
    if (!text.trim()) return;

    // Use authentic Scam Spotter scoring engine
    const result: ScanResult = analyzeMessage(text);
    const firedIds = new Set(result.breakdown.map((b) => b.ruleId));
    const safeSteps = generateSafeNextSteps(firedIds, result.riskLevel);

    this.renderResult(result, text, safeSteps);
  }

  private renderResult(result: ScanResult, rawText: string, safeSteps: ActionStep[]) {
    // 1. Score & Risk Badge
    if (this.scoreValueEl) {
      this.scoreValueEl.textContent = `${result.score}/100`;
    }

    if (this.riskBadgeEl) {
      this.riskBadgeEl.textContent = `${result.riskLevel} RISK`;
      this.riskBadgeEl.className = `metic-risk-badge risk-${result.riskLevel.toLowerCase()}`;
    }

    // 2. Highlight phrases in text
    if (this.highlightedTextMount) {
      this.renderHighlightedText(rawText, result);
    }

    // 3. Breakdown list
    if (this.breakdownListMount) {
      if (result.breakdown.length === 0) {
        this.breakdownListMount.innerHTML = `
          <div class="metic-empty-breakdown" style="padding: 12px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 4px; color: #16a34a; font-size: 12px;">
            ✓ No heuristic threat indicators fired. Zero coercion signals identified.
          </div>
        `;
      } else {
        this.breakdownListMount.innerHTML = result.breakdown
          .map((item) => {
            return `
            <div class="metic-demo-breakdown-row" data-rule="${escapeAttr(item.ruleId)}">
              <div class="breakdown-info">
                <span class="breakdown-category">${escapeHtml(item.category)}</span>
                <strong class="breakdown-name">${escapeHtml(item.label)}</strong>
                <p class="breakdown-reason">${escapeHtml(item.explanation)}</p>
              </div>
              <div class="breakdown-points-badge">+${item.awardedPoints}</div>
            </div>
          `;
          })
          .join('');
      }
    }

    // 4. Safe Next Steps
    if (this.safeStepsMount) {
      this.safeStepsMount.innerHTML = safeSteps
        .map((step) => {
          return `
          <li class="metic-safe-step-item">
            <span class="step-check">✓</span>
            <span><strong>${escapeHtml(step.verb)}:</strong> ${escapeHtml(step.instruction)}</span>
          </li>
        `;
        })
        .join('');
    }
  }

  private renderHighlightedText(rawText: string, result: ScanResult) {
    if (!this.highlightedTextMount) return;

    if (!result.activeEvidence || result.activeEvidence.length === 0) {
      this.highlightedTextMount.innerHTML = `<p class="metic-demo-text-clean">${escapeHtml(rawText)}</p>`;
      return;
    }

    // Create lookup map from ruleId to awardedPoints
    const pointsMap = new Map<string, number>();
    for (const b of result.breakdown) {
      pointsMap.set(b.ruleId, b.awardedPoints);
    }

    // Sort evidence spans by startIndex ascending
    const sorted = [...result.activeEvidence].sort((a, b) => a.startIndex - b.startIndex);

    let html = '';
    let lastIndex = 0;

    for (const ev of sorted) {
      if (ev.startIndex < lastIndex) {
        continue; // skip overlapping for clean inline display
      }

      // Preceding benign text
      if (ev.startIndex > lastIndex) {
        html += escapeHtml(rawText.substring(lastIndex, ev.startIndex));
      }

      const matchText = rawText.substring(ev.startIndex, ev.endIndex);
      const awarded = pointsMap.get(ev.ruleId) ?? 0;
      html += `<mark class="metic-evidence-highlight" title="${escapeAttr(ev.ruleLabel)} (+${awarded})">${escapeHtml(
        matchText
      )}<span class="metic-evidence-subtag">+${awarded}</span></mark>`;

      lastIndex = ev.endIndex;
    }

    if (lastIndex < rawText.length) {
      html += escapeHtml(rawText.substring(lastIndex));
    }

    this.highlightedTextMount.innerHTML = `<p class="metic-demo-text-annotated">${html}</p>`;
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str: string): string {
  return str.replace(/"/g, '&quot;');
}

export const liveDemo = new LiveDemoController();
