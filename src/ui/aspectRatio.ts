/**
 * Scam Spotter — Universal Device & Aspect Ratio Auto-Detection Engine
 * 
 * Automatically detects whether the user is on a mobile phone, tablet, laptop,
 * or ultrawide desktop, computes the exact aspect ratio (e.g. 9:16, 9:19.5, 16:9, 16:10, 21:9),
 * and dynamically adapts the UI container geometry, typography, lens scales, and layouts.
 */

export type DeviceType = 'mobile' | 'tablet' | 'laptop' | 'ultrawide';
export type OrientationType = 'portrait' | 'landscape';
export type AspectRatioPreset = 'auto' | 'mobile-9-19' | 'mobile-9-16' | 'tablet-4-3' | 'laptop-16-9' | 'ultrawide-21-9';

export interface DeviceAspectMetrics {
  width: number;
  height: number;
  ratio: number;
  ratioFormatted: string;
  closestStandard: string;
  deviceType: DeviceType;
  orientation: OrientationType;
  isTouch: boolean;
  scaleFactor: number;
  containerMaxWidth: string;
}

export class AspectRatioDetector {
  private currentMetrics: DeviceAspectMetrics | null = null;
  private forcedPreset: AspectRatioPreset = 'auto';
  private badgeEl: HTMLElement | null = null;
  private listeners: Array<(metrics: DeviceAspectMetrics) => void> = [];

  constructor() {
    this.handleResize = this.handleResize.bind(this);
  }

  public init() {
    // 1. Initial detection and styling injection
    this.detectAndApply();

    // 2. Window and orientation listeners
    window.addEventListener('resize', this.handleResize, { passive: true });
    window.addEventListener('orientationchange', this.handleResize, { passive: true });

    if (window.screen && window.screen.orientation) {
      window.screen.orientation.addEventListener('change', this.handleResize);
    }

    // 3. Render quick aspect ratio preview & status pill in the UI
    this.renderStatusBadge();
  }

  public subscribe(listener: (metrics: DeviceAspectMetrics) => void) {
    this.listeners.push(listener);
    if (this.currentMetrics) {
      listener(this.currentMetrics);
    }
  }

  public getMetrics(): DeviceAspectMetrics {
    if (!this.currentMetrics) {
      this.detectAndApply();
    }
    return this.currentMetrics!;
  }

  public setPreset(preset: AspectRatioPreset) {
    this.forcedPreset = preset;
    this.detectAndApply();
    this.updateStatusBadge();
  }

  public getPreset(): AspectRatioPreset {
    return this.forcedPreset;
  }

  private handleResize() {
    window.requestAnimationFrame(() => {
      this.detectAndApply();
      this.updateStatusBadge();
    });
  }

  public detectAndApply(): DeviceAspectMetrics {
    let width = window.innerWidth;
    let height = window.innerHeight;

    // Handle manual simulation preview presets if activated
    if (this.forcedPreset !== 'auto') {
      const simulated = this.getSimulatedDimensions(this.forcedPreset, width, height);
      width = simulated.width;
      height = simulated.height;
    }

    const ratio = width / Math.max(1, height);
    const orientation: OrientationType = ratio < 1.0 ? 'portrait' : 'landscape';
    const isTouch = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);

    // Classify Device Form Factor
    let deviceType: DeviceType = 'laptop';
    let closestStandard = '16:9';
    let scaleFactor = 1.0;
    let containerMaxWidth = '1320px';

    if (orientation === 'portrait') {
      // Portrait Mode -> Mobile Phone or Portrait Tablet
      if (width < 720 || (isTouch && width < 900)) {
        deviceType = 'mobile';
        scaleFactor = Math.min(1.0, Math.max(0.68, width / 440));
        containerMaxWidth = '100%';

        // Determine closest standard mobile aspect ratio
        if (ratio <= 0.44) {
          closestStandard = '9:21 (Sony / Modern Tall)';
        } else if (ratio <= 0.47) {
          closestStandard = '9:19.5 (iPhone / Galaxy)';
        } else if (ratio <= 0.52) {
          closestStandard = '9:18 (Modern Android)';
        } else if (ratio <= 0.60) {
          closestStandard = '9:16 (Standard Phone)';
        } else {
          closestStandard = '3:4 (Portrait Tablet)';
          deviceType = 'tablet';
        }
      } else {
        deviceType = 'tablet';
        closestStandard = '3:4 (Portrait Tablet)';
        scaleFactor = 0.85;
        containerMaxWidth = '768px';
      }
    } else {
      // Landscape Mode -> Mobile Landscape, Tablet, Laptop, or Ultrawide
      if (height < 500 && isTouch) {
        deviceType = 'mobile';
        closestStandard = '19.5:9 (Phone Landscape)';
        scaleFactor = 0.72;
        containerMaxWidth = '100%';
      } else if (width <= 1024 && ratio <= 1.45) {
        deviceType = 'tablet';
        closestStandard = '4:3 (Landscape Tablet)';
        scaleFactor = 0.9;
        containerMaxWidth = '960px';
      } else if (ratio > 2.05) {
        deviceType = 'ultrawide';
        closestStandard = '21:9 (Ultrawide Monitor)';
        scaleFactor = 1.05;
        containerMaxWidth = '1560px';
      } else if (ratio >= 1.7) {
        deviceType = 'laptop';
        closestStandard = '16:9 (Standard Laptop)';
        scaleFactor = 1.0;
        containerMaxWidth = '1320px';
      } else if (ratio >= 1.55) {
        deviceType = 'laptop';
        closestStandard = '16:10 (MacBook / Productivity)';
        scaleFactor = 1.0;
        containerMaxWidth = '1280px';
      } else {
        deviceType = 'laptop';
        closestStandard = '3:2 (Surface / Laptop)';
        scaleFactor = 0.98;
        containerMaxWidth = '1200px';
      }
    }

    const ratioFormatted = ratio < 1.0 
      ? `1:${(1 / ratio).toFixed(2)}` 
      : `${ratio.toFixed(2)}:1`;

    const metrics: DeviceAspectMetrics = {
      width,
      height,
      ratio,
      ratioFormatted,
      closestStandard,
      deviceType,
      orientation,
      isTouch,
      scaleFactor,
      containerMaxWidth,
    };

    this.currentMetrics = metrics;

    // Apply attributes and CSS variables to document
    this.applyToDocument(metrics);

    // Notify listeners
    this.listeners.forEach((fn) => fn(metrics));

    return metrics;
  }

  private getSimulatedDimensions(preset: AspectRatioPreset, maxW: number, maxH: number): { width: number; height: number } {
    switch (preset) {
      case 'mobile-9-19': {
        const h = Math.min(maxH - 80, 844);
        const w = Math.round(h * (9 / 19.5));
        return { width: Math.min(w, maxW), height: h };
      }
      case 'mobile-9-16': {
        const h = Math.min(maxH - 80, 780);
        const w = Math.round(h * (9 / 16));
        return { width: Math.min(w, maxW), height: h };
      }
      case 'tablet-4-3': {
        const h = Math.min(maxH - 60, 800);
        const w = Math.round(h * (4 / 3));
        return { width: Math.min(w, maxW), height: h };
      }
      case 'laptop-16-9': {
        const w = Math.min(maxW, 1366);
        const h = Math.round(w * (9 / 16));
        return { width: w, height: Math.min(h, maxH) };
      }
      case 'ultrawide-21-9': {
        const w = Math.min(maxW, 1680);
        const h = Math.round(w * (9 / 21));
        return { width: w, height: Math.min(h, maxH) };
      }
      default:
        return { width: maxW, height: maxH };
    }
  }

  private applyToDocument(m: DeviceAspectMetrics) {
    const root = document.documentElement;
    const body = document.body;

    // 1. Data attributes on root & body
    root.setAttribute('data-device-type', m.deviceType);
    root.setAttribute('data-orientation', m.orientation);
    root.setAttribute('data-ratio-name', m.closestStandard.split(' ')[0]);
    root.setAttribute('data-aspect-ratio', m.ratioFormatted);

    body.setAttribute('data-device-type', m.deviceType);
    body.setAttribute('data-orientation', m.orientation);

    // 2. CSS Custom Variables for pixel-perfect layout adaption
    root.style.setProperty('--app-vw', `${m.width}px`);
    root.style.setProperty('--app-vh', `${m.height}px`);
    root.style.setProperty('--app-true-ratio', `${m.ratio}`);
    root.style.setProperty('--app-scale-factor', `${m.scaleFactor}`);
    root.style.setProperty('--app-container-max-w', m.containerMaxWidth);

    // Mobile-specific ergonomic metrics
    if (m.deviceType === 'mobile') {
      root.style.setProperty('--app-content-padding', '14px');
      root.style.setProperty('--app-card-radius', '12px');
      root.style.setProperty('--app-btn-touch-height', '48px');
      root.style.setProperty('--magnifier-lens-scale', '0.72');
      root.style.setProperty('--sidebar-display-mode', 'overlay');
    } else if (m.deviceType === 'tablet') {
      root.style.setProperty('--app-content-padding', '20px');
      root.style.setProperty('--app-card-radius', '14px');
      root.style.setProperty('--app-btn-touch-height', '44px');
      root.style.setProperty('--magnifier-lens-scale', '0.85');
      root.style.setProperty('--sidebar-display-mode', 'collapsible');
    } else {
      // Laptop / Ultrawide
      root.style.setProperty('--app-content-padding', '32px');
      root.style.setProperty('--app-card-radius', '16px');
      root.style.setProperty('--app-btn-touch-height', '40px');
      root.style.setProperty('--magnifier-lens-scale', '1.0');
      root.style.setProperty('--sidebar-display-mode', 'docked');
    }
  }

  private renderStatusBadge() {
    if (document.getElementById('aspectRatioPill')) return;

    const badge = document.createElement('div');
    badge.id = 'aspectRatioPill';
    badge.className = 'aspect-ratio-pill';
    badge.setAttribute('role', 'region');
    badge.setAttribute('aria-label', 'Aspect Ratio Auto-Detection Status');

    badge.innerHTML = `
      <div class="ar-pill-trigger" id="arPillTrigger" title="Click to inspect or simulate aspect ratios">
        <span class="ar-pill-icon" id="arPillIcon">💻</span>
        <span class="ar-pill-label" id="arPillLabel">Detecting...</span>
        <span class="ar-pill-chevron">⚙️</span>
      </div>
      <div class="ar-pill-menu" id="arPillMenu" style="display: none;">
        <div class="ar-menu-header">
          <strong>📐 Aspect Ratio & Device Adapter</strong>
          <span class="ar-menu-sub" id="arMenuSub">Auto-calibrating UI</span>
        </div>
        <div class="ar-menu-options">
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'auto' ? 'active' : ''}" data-preset="auto">
            <span>✨ Auto-Detect (Active)</span>
            <small id="arMenuAutoSub">Live Screen</small>
          </button>
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'mobile-9-19' ? 'active' : ''}" data-preset="mobile-9-19">
            <span>📱 Mobile Phone (9:19.5)</span>
            <small>iPhone / Galaxy</small>
          </button>
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'mobile-9-16' ? 'active' : ''}" data-preset="mobile-9-16">
            <span>📱 Mobile Phone (9:16)</span>
            <small>Standard Phone</small>
          </button>
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'tablet-4-3' ? 'active' : ''}" data-preset="tablet-4-3">
            <span>📟 Tablet (4:3)</span>
            <small>iPad / Tablet</small>
          </button>
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'laptop-16-9' ? 'active' : ''}" data-preset="laptop-16-9">
            <span>💻 Laptop (16:9)</span>
            <small>1080p Widescreen</small>
          </button>
          <button type="button" class="ar-menu-opt ${this.forcedPreset === 'ultrawide-21-9' ? 'active' : ''}" data-preset="ultrawide-21-9">
            <span>🖥️ Ultrawide (21:9)</span>
            <small>Wide Monitor</small>
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(badge);
    this.badgeEl = badge;

    // Toggle menu
    const trigger = badge.querySelector('#arPillTrigger');
    const menu = badge.querySelector('#arPillMenu') as HTMLElement;

    trigger?.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = menu.style.display !== 'none';
      menu.style.display = isVisible ? 'none' : 'block';
    });

    document.addEventListener('click', (e) => {
      if (!badge.contains(e.target as Node)) {
        menu.style.display = 'none';
      }
    });

    // Option clicks
    badge.querySelectorAll('.ar-menu-opt').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget as HTMLElement;
        const preset = target.getAttribute('data-preset') as AspectRatioPreset;
        if (preset) {
          this.setPreset(preset);
          badge.querySelectorAll('.ar-menu-opt').forEach((b) => b.classList.remove('active'));
          target.classList.add('active');
          menu.style.display = 'none';
        }
      });
    });

    this.updateStatusBadge();
  }

  private updateStatusBadge() {
    if (!this.badgeEl || !this.currentMetrics) return;

    const m = this.currentMetrics;
    const iconEl = this.badgeEl.querySelector('#arPillIcon');
    const labelEl = this.badgeEl.querySelector('#arPillLabel');
    const subEl = this.badgeEl.querySelector('#arMenuSub');
    const autoSubEl = this.badgeEl.querySelector('#arMenuAutoSub');

    let icon = '💻';
    if (m.deviceType === 'mobile') icon = '📱';
    else if (m.deviceType === 'tablet') icon = '📟';
    else if (m.deviceType === 'ultrawide') icon = '🖥️';

    if (iconEl) iconEl.textContent = icon;
    if (labelEl) {
      const modePrefix = this.forcedPreset === 'auto' ? '' : 'Sim: ';
      labelEl.textContent = `${modePrefix}${m.closestStandard.split(' ')[0]} • ${m.deviceType.toUpperCase()}`;
    }
    if (subEl) {
      subEl.textContent = `${m.width}×${m.height}px (${m.ratioFormatted}) • ${m.orientation}`;
    }
    if (autoSubEl) {
      autoSubEl.textContent = `${window.innerWidth}×${window.innerHeight}px`;
    }
  }
}

export const aspectRatioDetector = new AspectRatioDetector();
