import { HistoryItem, HistoryService } from '../services/history.js';

export interface DashboardMetrics {
  totalScans: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  highPercent: number;
  mediumPercent: number;
  lowPercent: number;
  topRules: { ruleId: string; count: number; percentage: number }[];
  repeatIndicators: { term: string; count: number }[];
  recentActivity: { dateStr: string; score: number; level: string }[];
}

export function computeDashboardMetrics(history: HistoryItem[]): DashboardMetrics {
  const totalScans = history.length;
  if (totalScans === 0) {
    return {
      totalScans: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      highPercent: 0,
      mediumPercent: 0,
      lowPercent: 0,
      topRules: [],
      repeatIndicators: [],
      recentActivity: [],
    };
  }

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  const ruleCounts = new Map<string, number>();
  const previewTerms = new Map<string, number>();

  for (const item of history) {
    if (item.riskLevel === 'HIGH') highCount++;
    else if (item.riskLevel === 'MEDIUM') mediumCount++;
    else lowCount++;

    for (const ruleId of item.ruleIds) {
      ruleCounts.set(ruleId, (ruleCounts.get(ruleId) || 0) + 1);
    }

    // Extract potential domain or phone token from preview to detect repeats
    const words = item.preview.toLowerCase().match(/[a-z0-9-]+\.[a-z]{2,}|\+?91\d{10}/gi) || [];
    for (const word of words) {
      previewTerms.set(word, (previewTerms.get(word) || 0) + 1);
    }
  }

  const topRules = Array.from(ruleCounts.entries())
    .map(([ruleId, count]) => ({
      ruleId,
      count,
      percentage: Math.round((count / totalScans) * 100),
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const repeatIndicators = Array.from(previewTerms.entries())
    .filter(([_, count]) => count > 1)
    .map(([term, count]) => ({ term, count }))
    .sort((a, b) => b.count - a.count);

  const recentActivity = history.slice(0, 7).map((item) => ({
    dateStr: new Date(item.createdAt).toLocaleDateString([], {
      month: 'short',
      day: 'numeric',
    }),
    score: item.score,
    level: item.riskLevel,
  }));

  return {
    totalScans,
    highCount,
    mediumCount,
    lowCount,
    highPercent: Math.round((highCount / totalScans) * 100),
    mediumPercent: Math.round((mediumCount / totalScans) * 100),
    lowPercent: Math.round((lowCount / totalScans) * 100),
    topRules,
    repeatIndicators,
    recentActivity,
  };
}

export function renderDashboardHtml(): string {
  const history = HistoryService.getHistory();
  const m = computeDashboardMetrics(history);

  if (m.totalScans === 0) {
    return `
      <div class="dashboard-empty-state">
        <div style="font-size: 2rem; margin-bottom: 8px;">📊</div>
        <h4>No Scans Performed Yet</h4>
        <p style="color: var(--text-muted); font-size: 0.9rem;">
          Run your first message scan to see analytics, threat trends, and detection breakdowns here.
        </p>
      </div>
    `;
  }

  const topRulesHtml = m.topRules
    .map(
      (r) => `
      <div class="dash-bar-row">
        <div class="dash-bar-label">
          <span>${r.ruleId.replace(/_/g, ' ')}</span>
          <span>${r.count} scans (${r.percentage}%)</span>
        </div>
        <div class="dash-bar-track">
          <div class="dash-bar-fill" style="width: ${r.percentage}%;"></div>
        </div>
      </div>
    `
    )
    .join('');

  const repeatsNotice =
    m.repeatIndicators.length > 0
      ? `
    <div class="repeat-indicator-box">
      <strong>⚠️ REPEAT_INDICATOR:</strong> The following suspicious identifiers appeared across multiple scans:
      <div style="margin-top: 6px;">
        ${m.repeatIndicators
          .map((rep) => `<span class="repeat-pill">${rep.term} (seen ${rep.count}x)</span>`)
          .join(' ')}
      </div>
      <small style="color: var(--text-muted); display: block; margin-top: 4px;">Informational notice — does not add points.</small>
    </div>
  `
      : '';

  return `
    <div class="dashboard-container">
      <div class="dashboard-metrics-grid">
        <!-- Widget 1: Total Scans -->
        <div class="dash-card">
          <div class="dash-metric-title">Total Scans</div>
          <div class="dash-metric-num">${m.totalScans}</div>
          <div class="dash-metric-sub">Stored locally on device</div>
        </div>

        <!-- Widget 2: High Risk -->
        <div class="dash-card high-border">
          <div class="dash-metric-title">Critical Threats</div>
          <div class="dash-metric-num text-high">${m.highCount}</div>
          <div class="dash-metric-sub">${m.highPercent}% of total scans</div>
        </div>

        <!-- Widget 3: Medium Risk -->
        <div class="dash-card med-border">
          <div class="dash-metric-title">Suspicious / Caution</div>
          <div class="dash-metric-num text-med">${m.mediumCount}</div>
          <div class="dash-metric-sub">${m.mediumPercent}% of total scans</div>
        </div>

        <!-- Widget 4: Low Risk -->
        <div class="dash-card low-border">
          <div class="dash-metric-title">Benign / Safe</div>
          <div class="dash-metric-num text-low">${m.lowCount}</div>
          <div class="dash-metric-sub">${m.lowPercent}% of total scans</div>
        </div>
      </div>

      <!-- Widget 5: Top Warning Types -->
      <div class="dash-panel">
        <h4 style="margin-bottom: 14px;">Top Detected Threat Signals</h4>
        ${topRulesHtml}
      </div>

      <!-- Widget 6: Repeat Indicators -->
      ${repeatsNotice}

      <div class="dashboard-footer-actions" style="margin-top: 20px; display: flex; justify-content: flex-end;">
        <button id="btnDashNewScan" class="btn-primary" type="button" style="padding: 10px 18px; font-size: 0.88rem;">
          ⚡ Start New Scan
        </button>
      </div>
    </div>
  `;
}
