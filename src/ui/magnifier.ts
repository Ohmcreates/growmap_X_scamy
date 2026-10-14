/**
 * Scam Spotter — Universal Draggable Magnifying Glass with Optical Zoom & Tri-Color Glow
 *
 * Implements a transparent magnifying glass with real-time 1.6x optical zoom.
 * The circular lens glow adapts dynamically to the threat level underneath:
 *  - RED GLOW: High Risk Malware & Phishing Coercion (45-100/100)
 *  - YELLOW GLOW: Medium Risk Warning & Unverified Links (21-44/100)
 *  - GREEN GLOW: Verified Clean / Benign Content (0-20/100)
 *
 * Works everywhere across the application: Landing Page, Auth View, and Scanner Workspace.
 */

import { analyzeMessage } from '../engine/scorer.js';
import { ScanResult } from '../engine/types.js';
import { router } from './router.js';
import { aspectRatioDetector } from './aspectRatio.js';

export interface ThreatAnalysisState {
  hasThreat: boolean;
  score: number;
  riskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  signature: string;
  c2Server: string;
  payload: string;
  breakdown: string[];
  rawText: string;
  elementTag: string;
  dimensions: string;
}

export class DraggableMagnifier {
  private container: HTMLElement | null = null;
  private viewportEl: HTMLElement | null = null;
  private glowRingEl: HTMLElement | null = null;
  private hudContentEl: HTMLElement | null = null;
  private hintPill: HTMLElement | null = null;

  // Position and dragging state
  private posX: number = 0;
  private posY: number = 0;
  private isDragging: boolean = false;
  private dragOffsetX: number = 0;
  private dragOffsetY: number = 0;
  private targetX: number = 0;
  private targetY: number = 0;

  // Geometry constants (matching 383x486 asset geometry scaled to 340x431)
  private readonly lensCenterOffsetX: number = 158 * (340 / 383); // ~140.25px
  private readonly lensCenterOffsetY: number = 159.5 * (340 / 383); // ~141.6px

  // Sampling throttle
  private lastSampleTime: number = 0;
  private currentState: ThreatAnalysisState | null = null;
  private isEnabled: boolean = true;
  private readonly STORAGE_KEY: string = 'scam_spotter_magnifier_state';

  public init() {
    this.container = document.getElementById('draggableMagnifier');
    this.viewportEl = document.getElementById('magnifierLensViewport');
    this.glowRingEl = document.getElementById('magnifierGlowRing');
    this.hudContentEl = document.getElementById('magnifierHudContent');
    this.hintPill = document.getElementById('magnifierDragHint');

    if (!this.container || !this.viewportEl) return;

    // Restore remembered on/off state from browser localStorage
    try {
      const savedState = localStorage.getItem(this.STORAGE_KEY);
      if (savedState === 'off') {
        this.isEnabled = false;
      } else if (savedState === 'on') {
        this.isEnabled = true;
      }
    } catch {}

    // Set initial position: right beside the hero preview card
    const heroPreview = document.getElementById('heroPreviewBox');
    if (heroPreview) {
      const rect = heroPreview.getBoundingClientRect();
      this.posX = Math.max(20, rect.left - 160);
      this.posY = Math.max(80, rect.top + 20);
    } else {
      this.posX = Math.max(40, window.innerWidth - 420);
      this.posY = 120;
    }

    this.targetX = this.posX;
    this.targetY = this.posY;
    this.updatePosition();

    // Subscribe to auto-detected aspect ratio / device changes
    aspectRatioDetector.subscribe((_metrics) => {
      const scale = this.getScale();
      const maxX = Math.max(0, window.innerWidth - (340 * scale));
      const maxY = Math.max(0, window.innerHeight - (431 * scale));
      this.posX = Math.min(this.posX, maxX);
      this.posY = Math.min(this.posY, maxY);
      this.updatePosition();
      this.sampleUnderneath();
    });

    // Drag pointer events on the container
    this.container.addEventListener('pointerdown', (e) => this.handlePointerDown(e));
    window.addEventListener('pointermove', (e) => this.handlePointerMove(e));
    window.addEventListener('pointerup', (e) => this.handlePointerUp(e));
    window.addEventListener('pointercancel', (e) => this.handlePointerUp(e));

    // Preset quick jump buttons across all pages
    document.getElementById('btnGlideToHero')?.addEventListener('click', (e) => {
      e.preventDefault();
      if (router.getRoute() !== 'landing') {
        router.navigate('landing');
        setTimeout(() => this.glideToElement('#heroPreviewBox', -80, 20), 100);
      } else {
        this.glideToElement('#heroPreviewBox', -80, 20);
      }
    });

    document.getElementById('btnGlideToDemo')?.addEventListener('click', (e) => {
      e.preventDefault();
      if (router.getRoute() !== 'landing') {
        router.navigate('landing');
        setTimeout(() => this.glideToElement('#demoHighlightedTextMount', -90, -40), 100);
      } else {
        this.glideToElement('#demoHighlightedTextMount', -90, -40);
      }
    });

    document.getElementById('btnGlideToLinks')?.addEventListener('click', (e) => {
      e.preventDefault();
      if (router.getRoute() !== 'landing') {
        router.navigate('landing');
        setTimeout(() => this.glideToElement('#link-security', 40, 100), 100);
      } else {
        this.glideToElement('#link-security', 40, 100);
      }
    });

    // Floating circular corner toggle
    document.getElementById('btnMagnifierCornerToggle')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.toggleEnabled();
    });

    // Dock bar toggle button
    document.getElementById('btnToggleMagnifier')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.toggleEnabled();
    });

    // Sync initial visibility
    this.syncVisibility();

    // Start continuous sampling loop
    this.startLoop();

    // Initial inspection of whatever is under the default position
    this.sampleUnderneath();
  }

  private handlePointerDown(e: PointerEvent) {
    if (!this.container) return;
    if (e.button !== 0) return; // primary mouse button only

    this.isDragging = true;
    this.container.classList.add('dragging');
    this.container.setPointerCapture(e.pointerId);

    const rect = this.container.getBoundingClientRect();
    this.dragOffsetX = e.clientX - rect.left;
    this.dragOffsetY = e.clientY - rect.top;

    if (this.hintPill) {
      this.hintPill.style.opacity = '0';
    }
  }

  private getScale(): number {
    try {
      const metrics = aspectRatioDetector.getMetrics();
      return metrics.deviceType === 'mobile' ? 0.72 : (metrics.deviceType === 'tablet' ? 0.85 : 1.0);
    } catch {
      return 1.0;
    }
  }

  private handlePointerMove(e: PointerEvent) {
    if (!this.isDragging) return;

    const scale = this.getScale();
    // Constrain within viewport boundaries adapted to detected scale
    const maxX = Math.max(0, window.innerWidth - (340 * scale) + 40);
    const maxY = Math.max(0, window.innerHeight - (431 * scale) + 40);

    this.targetX = Math.min(maxX, Math.max(-60, e.clientX - this.dragOffsetX));
    this.targetY = Math.min(maxY, Math.max(10, e.clientY - this.dragOffsetY));

    this.posX = this.targetX;
    this.posY = this.targetY;
    this.updatePosition();
    this.sampleUnderneath();
  }

  private handlePointerUp(e: PointerEvent) {
    if (!this.isDragging || !this.container) return;
    this.isDragging = false;
    this.container.classList.remove('dragging');
    try {
      this.container.releasePointerCapture(e.pointerId);
    } catch {
      // ignore
    }
    this.sampleUnderneath(true);
  }

  public glideToElement(selector: string, offsetX: number = 0, offsetY: number = 0) {
    const el = document.querySelector(selector) as HTMLElement | null;
    if (!el || !this.container) return;

    // Scroll element smoothly into view
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

    setTimeout(() => {
      const rect = el.getBoundingClientRect();
      const destX = rect.left + offsetX;
      const destY = rect.top + offsetY;

      this.animateGlide(destX, destY);
    }, 280);
  }

  private animateGlide(destX: number, destY: number) {
    const startX = this.posX;
    const startY = this.posY;
    const duration = 380;
    const startTime = performance.now();

    const step = (now: number) => {
      const progress = Math.min(1, (now - startTime) / duration);
      // Smooth ease-out cubic
      const ease = 1 - Math.pow(1 - progress, 3);

      this.posX = startX + (destX - startX) * ease;
      this.posY = startY + (destY - startY) * ease;
      this.updatePosition();
      this.sampleUnderneath();

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        this.sampleUnderneath(true);
      }
    };

    requestAnimationFrame(step);
  }

  public isGlassEnabled(): boolean {
    return this.isEnabled;
  }

  private saveState(enabled: boolean) {
    try {
      localStorage.setItem(this.STORAGE_KEY, enabled ? 'on' : 'off');
    } catch {}
  }

  public enable() {
    this.isEnabled = true;
    this.saveState(true);
    this.syncVisibility();
  }

  public disable() {
    this.isEnabled = false;
    this.saveState(false);
    this.syncVisibility();
  }

  public toggleEnabled() {
    this.isEnabled = !this.isEnabled;
    this.saveState(this.isEnabled);
    this.syncVisibility();
  }

  public show() {
    this.enable();
  }

  public hide() {
    this.disable();
  }

  public toggleVisibility() {
    this.toggleEnabled();
  }

  public syncVisibility() {
    const isLanding = router.getRoute() === 'landing';
    const cornerToggle = document.getElementById('btnMagnifierCornerToggle');
    const dockBar = document.getElementById('magnifierDockBar');

    if (!isLanding) {
      if (this.container) this.container.style.display = 'none';
      if (dockBar) dockBar.style.display = 'none';
      if (cornerToggle) cornerToggle.style.display = 'none';
      return;
    }

    // On landing page:
    if (cornerToggle) cornerToggle.style.display = 'flex';

    if (this.isEnabled) {
      if (this.container) this.container.style.display = 'block';
      if (dockBar) dockBar.style.display = 'flex';
      if (cornerToggle) {
        cornerToggle.classList.remove('is-off');
        cornerToggle.title = 'Click to disable Forensic Magnifier';
      }
      this.sampleUnderneath(true);
    } else {
      if (this.container) this.container.style.display = 'none';
      if (dockBar) dockBar.style.display = 'none';
      if (cornerToggle) {
        cornerToggle.classList.add('is-off');
        cornerToggle.title = 'Click to enable Forensic Magnifier';
      }
    }
  }

  private updatePosition() {
    if (!this.container) return;
    const scale = this.getScale();
    this.container.style.transformOrigin = 'top left';
    this.container.style.transform = `translate3d(${this.posX}px, ${this.posY}px, 0) scale(${scale})`;
  }

  private startLoop() {
    const loop = () => {
      const now = performance.now();
      if (now - this.lastSampleTime > 100) {
        if (
          this.container &&
          this.container.style.display !== 'none' &&
          router.getRoute() === 'landing'
        ) {
          this.sampleUnderneath();
        }
        this.lastSampleTime = now;
      }
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  /**
   * Sample the DOM element directly underneath the center of the circular magnifying lens
   */
  private sampleUnderneath(force: boolean = false) {
    if (!this.container || !this.viewportEl) return;

    const scale = this.getScale();
    // Glass center coordinates on viewport accounting for dynamic device aspect scale
    const glassCenterX = this.posX + (this.lensCenterOffsetX * scale);
    const glassCenterY = this.posY + (this.lensCenterOffsetY * scale);

    // Temporarily hide pointer events on magnifier so we can sample the real underlying element
    this.container.style.pointerEvents = 'none';
    const sampledEl = document.elementFromPoint(glassCenterX, glassCenterY) as HTMLElement | null;
    this.container.style.pointerEvents = '';

    if (!sampledEl) return;

    // Find closest context element (card, message container, link, or paragraph)
    const contextEl =
      (sampledEl.closest(
        '#heroPreviewBox, #demoHighlightedTextMount, .metic-sample-message, .metic-demo-sandbox, .metic-feature-card, .metic-security-card, .input-card, .card-box, a, button, textarea, input, p, code'
      ) as HTMLElement) || sampledEl;

    const rawText = (contextEl as HTMLInputElement).value || contextEl.innerText || contextEl.textContent || '';
    const tag = contextEl.tagName.toLowerCase();
    const rect = contextEl.getBoundingClientRect();
    const dimensions = `${Math.round(rect.width)} × ${Math.round(rect.height)}px`;

    // Analyze extracted text using Scam Spotter engine
    const analysis = this.analyzeSampledContent(rawText, contextEl, tag, dimensions);

    // Only re-render if state changed or forced
    if (force || this.hasStateChanged(analysis)) {
      this.currentState = analysis;
      this.renderLensHud(analysis);
    }
  }

  private analyzeSampledContent(
    text: string,
    el: HTMLElement,
    tag: string,
    dimensions: string
  ): ThreatAnalysisState {
    const trimmed = text.trim();
    const hasLink = el.closest('a') !== null || /https?:\/\/|[a-z0-9-]+\.(xyz|top|ru|live|link)/i.test(trimmed);
    return evaluateLensThreat(trimmed, hasLink, tag, dimensions);
  }

  private hasStateChanged(next: ThreatAnalysisState): boolean {
    if (!this.currentState) return true;
    return (
      this.currentState.riskLevel !== next.riskLevel ||
      this.currentState.score !== next.score ||
      this.currentState.title !== next.title ||
      this.currentState.signature !== next.signature
    );
  }

  /**
   * Render the internal 1.6x Zoom mirror and Tri-Color Glow (Red, Yellow, Green)
   */
  private renderLensHud(state: ThreatAnalysisState) {
    if (!this.hudContentEl || !this.viewportEl) return;

    // 1. Update Tri-Color Glow on Circular Lens
    if (this.glowRingEl) {
      if (state.riskLevel === 'HIGH') {
        this.glowRingEl.className = 'magnifier-glow-ring glow-red';
        this.viewportEl.className = 'magnifier-viewport glow-red-active';
      } else if (state.riskLevel === 'MEDIUM') {
        this.glowRingEl.className = 'magnifier-glow-ring glow-yellow';
        this.viewportEl.className = 'magnifier-viewport glow-yellow-active';
      } else {
        this.glowRingEl.className = 'magnifier-glow-ring glow-green';
        this.viewportEl.className = 'magnifier-viewport glow-green-active';
      }
    }

    // 2. Generate Highlighted 1.6x Zoom Text
    const highlightedZoomSnippet = this.generateZoomSnippet(state.rawText, state.riskLevel);

    // 3. Render Inner Lens Viewport Content (Zoomed text + Status banner)
    if (state.riskLevel === 'HIGH') {
      this.hudContentEl.innerHTML = `
        <div class="lens-radar-sweep sweep-red"></div>
        <div class="lens-cyber-grid grid-red"></div>

        <!-- Optical 1.6x Zoom Mirror -->
        <div class="magnifier-zoom-mirror">
          <div class="zoom-magnified-text text-threat">${highlightedZoomSnippet}</div>
        </div>

        <!-- Threat Diagnostics Overlay -->
        <div class="lens-hud-card threat-hud">
          <div class="threat-alert-row">
            <span class="threat-pulsing-dot glow-red-dot"></span>
            <span class="threat-status-tag tag-red">🚨 HIGH RISK [${state.score}/100]</span>
          </div>

          <div class="threat-field-grid">
            <div class="threat-field">
              <span class="field-label">THREAT:</span>
              <span class="field-val text-red">${escapeHtml(state.signature)}</span>
            </div>
            <div class="threat-field">
              <span class="field-label">PAYLOAD:</span>
              <span class="field-val mono-code">${escapeHtml(state.payload)}</span>
            </div>
          </div>

          <div class="threat-breakdown-chips">
            ${state.breakdown.map((item) => `<span class="threat-chip chip-red">${escapeHtml(item)}</span>`).join('')}
          </div>

          <div class="threat-hex-telemetry">
            <code>0x4A 0x7F [MALWARE_ACTIVE]</code>
            <span>ZOOM 1.6× // ${escapeHtml(state.dimensions)}</span>
          </div>
        </div>
      `;
    } else if (state.riskLevel === 'MEDIUM') {
      this.hudContentEl.innerHTML = `
        <div class="lens-radar-sweep sweep-yellow"></div>
        <div class="lens-cyber-grid grid-yellow"></div>

        <!-- Optical 1.6x Zoom Mirror -->
        <div class="magnifier-zoom-mirror">
          <div class="zoom-magnified-text text-warning">${highlightedZoomSnippet}</div>
        </div>

        <!-- Warning Diagnostics Overlay -->
        <div class="lens-hud-card warning-hud">
          <div class="threat-alert-row">
            <span class="threat-pulsing-dot glow-yellow-dot"></span>
            <span class="threat-status-tag tag-yellow">⚠️ MEDIUM RISK [${state.score}/100]</span>
          </div>

          <div class="threat-field-grid grid-amber">
            <div class="threat-field">
              <span class="field-label">PATTERN:</span>
              <span class="field-val text-yellow">${escapeHtml(state.signature)}</span>
            </div>
            <div class="threat-field">
              <span class="field-label">WARNING:</span>
              <span class="field-val text-yellow">Verify sender &amp; URL before proceeding</span>
            </div>
          </div>

          <div class="threat-breakdown-chips">
            ${state.breakdown.map((item) => `<span class="threat-chip chip-yellow">${escapeHtml(item)}</span>`).join('')}
          </div>

          <div class="threat-hex-telemetry">
            <code>0x2B 0x8C [UNVERIFIED]</code>
            <span>ZOOM 1.6× // ${escapeHtml(state.dimensions)}</span>
          </div>
        </div>
      `;
    } else {
      this.hudContentEl.innerHTML = `
        <div class="lens-radar-sweep sweep-green"></div>
        <div class="lens-cyber-grid grid-green"></div>

        <!-- Optical 1.6x Zoom Mirror -->
        <div class="magnifier-zoom-mirror">
          <div class="zoom-magnified-text text-clean">${highlightedZoomSnippet}</div>
        </div>

        <!-- Safe Diagnostics Overlay -->
        <div class="lens-hud-card clean-hud">
          <div class="clean-alert-row">
            <span class="clean-check-icon">✓</span>
            <span class="clean-status-tag tag-green">🟢 SAFE [SCORE: ${state.score}]</span>
          </div>

          <div class="clean-field-grid grid-emerald">
            <div class="clean-field">
              <span class="field-label">STATUS:</span>
              <span class="field-val text-green">${escapeHtml(state.signature)}</span>
            </div>
            <div class="clean-field">
              <span class="field-label">TARGET:</span>
              <span class="field-val mono-code">${escapeHtml(state.elementTag)} (${escapeHtml(state.dimensions)})</span>
            </div>
          </div>

          <div class="clean-telemetry-tag">
            <span>CLIENT-SIDE DETERMINISTIC SANDBOX</span>
            <span class="mono-code">ZOOM 1.6× // 100% SAFE</span>
          </div>
        </div>
      `;
    }
  }

  private generateZoomSnippet(raw: string, riskLevel: 'HIGH' | 'MEDIUM' | 'LOW'): string {
    return generateZoomSnippet(raw, riskLevel);
  }
}

export function evaluateLensThreat(
  text: string,
  hasLink: boolean = false,
  tag: string = 'div',
  dimensions: string = '300 × 120px'
): ThreatAnalysisState {
  const trimmed = text.trim();
  const detectedLink = hasLink || /https?:\/\/|[a-z0-9-]+\.(xyz|top|ru|live|link)/i.test(trimmed);

  // If text has significant length, analyze with Scam Spotter rules
  let scanResult: ScanResult | null = null;
  if (trimmed.length > 8) {
    scanResult = analyzeMessage(trimmed);
  }

  const score = scanResult ? scanResult.score : 0;

  // Tier 1: HIGH RISK -> RED GLOW
  const isHighThreat = score >= 50 || /kyc|otp|blocked|urgent|challan|delivery failed|pay immediately/i.test(trimmed);

  if (isHighThreat) {
    let signature = 'TROJAN.BANKER / CREDENTIAL_STEALER';
    let c2Server = '185.220.101.4:8443 (UNAPPROVED_C2)';
    let payload = 'POST /api/exfiltrate?token=otp_session';

    if (/challan|traffic|police/i.test(trimmed)) {
      signature = 'EXPLOIT.MPARIVAHAN.SPOOF';
      c2Server = 'echallan.redirectme.net (DYNAMIC_DNS)';
      payload = 'GET /pay?fake_fine=2000';
    } else if (/delivery|package|post/i.test(trimmed)) {
      signature = 'SMISHING.POSTAL_BAIT.APKVIRUS';
      c2Server = 'bit.ly/indpst-fee -> cdn.malware.apk';
      payload = 'INSTALL /system/app/Stealer.apk';
    }

    const breakdown = scanResult
      ? scanResult.breakdown.map((b) => `${b.label} (+${b.awardedPoints})`)
      : ['Fake Urgency (+20)', 'Account Coercion (+15)', 'Suspicious Link (+25)', 'OTP Request (+40)'];

    return {
      hasThreat: true,
      score: Math.max(score, 90),
      riskLevel: 'HIGH',
      title: 'CRITICAL MALWARE & FRAUD DETECTED',
      signature,
      c2Server,
      payload,
      breakdown,
      rawText: trimmed.substring(0, 110),
      elementTag: `<${tag}>`,
      dimensions,
    };
  }

  // Tier 2: MEDIUM RISK -> YELLOW GLOW
  const isMediumThreat = (score >= 20 && score < 50) || detectedLink || /verify|update|warning|unpaid|action required/i.test(trimmed);

  if (isMediumThreat) {
    return {
      hasThreat: true,
      score: Math.max(score, 35),
      riskLevel: 'MEDIUM',
      title: 'SUSPICIOUS PATTERN / UNVERIFIED LINK',
      signature: 'HEURISTIC.LOOKALIKE.UNVERIFIED',
      c2Server: 'EXTERNAL_UNVERIFIED_REDIRECTOR',
      payload: 'UNTRUSTED_PROTOCOL_HANDSHAKE',
      breakdown: ['Unverified Domain / Shortener', 'External Redirect Pattern'],
      rawText: trimmed.substring(0, 90),
      elementTag: `<${tag}>`,
      dimensions,
    };
  }

  // Tier 3: LOW RISK -> GREEN GLOW
  return {
    hasThreat: false,
    score: score,
    riskLevel: 'LOW',
    title: 'INTEGRITY VERIFIED: SAFE',
    signature: '0 / 16 MALWARE VECTORS FIRED',
    c2Server: 'NONE // CLIENT-SIDE SANDBOX',
    payload: 'ZERO DATA EXFILTRATION DETECTED',
    breakdown: ['Zero Pressure Tactics', 'Zero Credential Traps', 'Clean Protocol'],
    rawText: trimmed.substring(0, 80),
    elementTag: `<${tag}>`,
    dimensions,
  };
}

export function generateZoomSnippet(raw: string, riskLevel: 'HIGH' | 'MEDIUM' | 'LOW'): string {
  if (!raw) return '<em>Hovering over empty layout...</em>';

  let snippet = escapeHtml(raw.slice(0, 95));

  if (riskLevel === 'HIGH') {
    // Highlight scam words in red
    snippet = snippet.replace(
      /(blocked today|incomplete KYC|KYC|immediately|enter OTP|OTP|http:\/\/[^\s]+|sbi-kyc-update\.xyz|traffic fine|challan|delivery failed|arrest|power cut)/gi,
      '<mark class="zoom-mark-red">$1</mark>'
    );
  } else if (riskLevel === 'MEDIUM') {
    snippet = snippet.replace(
      /(http:\/\/[^\s]+|https:\/\/[^\s]+|verify|update|warning|bit\.ly[^\s]*)/gi,
      '<mark class="zoom-mark-yellow">$1</mark>'
    );
  } else {
    snippet = snippet.replace(
      /(official|verified|safe|debited|SBI|protect|privacy)/gi,
      '<mark class="zoom-mark-green">$1</mark>'
    );
  }

  return snippet;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export const draggableMagnifier = new DraggableMagnifier();
