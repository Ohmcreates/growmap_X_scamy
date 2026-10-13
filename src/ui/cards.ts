import { EMERGENCY_PLAN, generateSafeNextSteps } from '../engine/safeSteps.js';
import { RuleBreakdownItem, ScanResult, UnmatchedRuleItem } from '../engine/types.js';
import { PRICING_TIERS, UNIT_ECONOMICS } from '../services/monetization.js';

export function renderScoreGauge(result: ScanResult): string {
  const levelClass = result.riskLevel.toLowerCase();
  const icon =
    result.riskLevel === 'HIGH'
      ? '🛡️'
      : result.riskLevel === 'MEDIUM'
      ? '⚠️'
      : '✅';

  return `
    <div class="result-header-card level-${levelClass}">
      <div class="gauge-top-row">
        <div class="risk-badge">
          <span class="badge-icon">${icon}</span>
          <span class="badge-text">${result.riskLevel} RISK</span>
        </div>
        <div class="score-display">
          <span class="score-value">${result.score}</span>
          <span class="score-denom">/ 100</span>
        </div>
      </div>
      <h3 class="result-headline">${result.headline}</h3>
      <p class="result-summary">${result.summary}</p>
      ${
        result.scamProfile
          ? `
        <div class="profile-attribution-tag">
          <span class="tag-label">Identified Scam Pattern:</span>
          <strong>${result.scamProfile.name}</strong>
        </div>
      `
          : ''
      }
      ${
        result.floorApplied
          ? `
        <div class="floor-rule-notice">
          <strong>⚠️ Floor Rule Applied:</strong> Verified malicious indicator detected. Minimum score locked to 60 (High Risk).
        </div>
      `
          : ''
      }
    </div>
  `;
}

export function renderBreakdownCards(breakdown: RuleBreakdownItem[]): string {
  if (breakdown.length === 0) {
    return `
      <div class="empty-breakdown-card">
        <div class="empty-icon">🛡️</div>
        <h4>No Suspicious Warning Signs Found</h4>
        <p>None of the active detection rules fired on this message. However, unexpected requests should always be treated with healthy caution.</p>
      </div>
    `;
  }

  const cardsHtml = breakdown
    .map((item) => {
      const categoryClass = item.category.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      const pointBadge = item.cappedByGroup
        ? `<span class="points-badge capped">+0 <small>(group capped)</small></span>`
        : `<span class="points-badge active">+${item.awardedPoints} pts</span>`;

      const quotesHtml = item.evidence
        .map((e) => `<code class="matched-quote">"${escapeHtml(e.matchedText)}"</code>`)
        .slice(0, 3)
        .join(' ');

      return `
        <div class="explanation-card cat-${categoryClass}" id="card-${item.ruleId}">
          <div class="card-header">
            <div class="card-title-group">
              <span class="card-category">${item.category}</span>
              <h4 class="card-title">${item.label}</h4>
            </div>
            ${pointBadge}
          </div>
          <p class="card-explanation">${item.explanation}</p>
          <div class="card-evidence-row">
            <span class="evidence-label">Detected evidence:</span>
            ${quotesHtml}
          </div>
        </div>
      `;
    })
    .join('');

  // Total arithmetic calculation line
  const pointSumFormula = breakdown
    .map((item) => item.awardedPoints)
    .join(' + ');
  const totalAwarded = breakdown.reduce((sum, item) => sum + item.awardedPoints, 0);

  return `
    <div class="breakdown-cards-list">
      ${cardsHtml}
      <div class="breakdown-total-row">
        <div class="formula-label">Total Score Calculation:</div>
        <div class="formula-math">${pointSumFormula} = <strong>${Math.min(100, totalAwarded)} / 100</strong></div>
      </div>
      <p class="score-disclaimer">
        ℹ️ Note: This score is a deterministic estimate of detected warning signs, not a probability that fraud has occurred.
      </p>
    </div>
  `;
}

export function renderUnmatchedChecks(unmatched: UnmatchedRuleItem[]): string {
  const items = unmatched
    .map(
      (u) => `
      <li class="unmatched-item">
        <span class="unmatched-check">✓</span>
        <span class="unmatched-label">${u.label}</span>
        <span class="unmatched-category">(${u.category})</span>
      </li>
    `
    )
    .join('');

  return `
    <details class="unmatched-drawer">
      <summary class="unmatched-summary">
        <span>Checks that found nothing (${unmatched.length} clean checks)</span>
        <span class="expand-icon">▾</span>
      </summary>
      <ul class="unmatched-list">
        ${items}
      </ul>
    </details>
  `;
}

export function renderNextSteps(result: ScanResult): string {
  const firedIds = new Set(result.breakdown.map((b) => b.ruleId));
  const steps = generateSafeNextSteps(firedIds, result.riskLevel);

  const stepsHtml = steps
    .map(
      (step, idx) => `
      <div class="next-step-row priority-${step.priority.toLowerCase()}">
        <div class="step-num">${idx + 1}</div>
        <div class="step-content">
          <strong>${step.verb}:</strong> ${step.instruction}
        </div>
      </div>
    `
    )
    .join('');

  const emergencyCard =
    result.riskLevel === 'HIGH' || result.riskLevel === 'MEDIUM'
      ? `
    <div class="emergency-shared-card">
      <div class="emergency-header">
        <span class="emergency-icon">🚨</span>
        <h4>Already clicked a link or entered your OTP / PIN?</h4>
      </div>
      <p>Act quickly during the golden hour to prevent unauthorized fund transfer:</p>
      <ul class="emergency-list">
        ${EMERGENCY_PLAN.alreadySharedSteps.map((s) => `<li>${s}</li>`).join('')}
      </ul>
      <div class="helpline-actions">
        <a href="${EMERGENCY_PLAN.helplineUrl}" class="helpline-btn phone-btn">
          📞 Call Cyber Helpline: 1930
        </a>
        <a href="${EMERGENCY_PLAN.portalUrl}" target="_blank" rel="noopener" class="helpline-btn portal-btn">
          🌐 Visit cybercrime.gov.in
        </a>
      </div>
    </div>
  `
      : '';

  return `
    <div class="next-steps-container">
      <h3 class="section-title">Recommended Safe Next Steps</h3>
      <div class="steps-list">
        ${stepsHtml}
      </div>
      ${emergencyCard}
    </div>
  `;
}

export function renderPricingModal(): string {
  const cardsHtml = PRICING_TIERS.map(
    (tier) => `
    <div class="pricing-card ${tier.id === 'PREMIUM' ? 'featured' : ''}">
      ${tier.badge ? `<div class="tier-badge">${tier.badge}</div>` : ''}
      <h3 class="tier-name">${tier.name}</h3>
      <div class="tier-price-row">
        <span class="tier-price">${tier.price}</span>
        <span class="tier-period">${tier.period}</span>
      </div>
      <p class="tier-audience"><em>${tier.targetAudience}</em></p>
      <ul class="tier-features">
        ${tier.features.map((f) => `<li>✓ ${f}</li>`).join('')}
      </ul>
      <button class="tier-btn ${tier.id === 'PREMIUM' ? 'primary' : 'secondary'}">
        ${tier.ctaLabel}
      </button>
    </div>
  `
  ).join('');

  return `
    <div class="pricing-modal-content">
      <div class="modal-header">
        <h2>Sustainable Scam Defense Plans</h2>
        <p>Scam Spotter is free for personal awareness, supported by premium family tools and institutional FinTech APIs.</p>
      </div>
      <div class="pricing-grid">
        ${cardsHtml}
      </div>
      <div class="unit-economics-callout">
        <h4>Transparent Sustainability Economics</h4>
        <div class="economics-grid">
          <div><strong>Core Rule Cost:</strong> ${UNIT_ECONOMICS.ruleCostPerScan}</div>
          <div><strong>AI Provider Cost:</strong> ${UNIT_ECONOMICS.aiCostPerScan}</div>
          <div><strong>Paid Tier Margin:</strong> ${UNIT_ECONOMICS.grossMarginOnPaid}</div>
          <div><strong>Break-Even:</strong> ${UNIT_ECONOMICS.breakEvenThreshold}</div>
        </div>
      </div>
    </div>
  `;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
