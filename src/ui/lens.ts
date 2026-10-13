/**
 * Scam Spotter — Signature Interactive Magnifying Lens (Metic.studio inspired)
 *
 * Provides a circular inspection loupe that reveals the technical architecture,
 * layout grid lines, container boundaries, spacing measurements, alignment guides,
 * and real computed DOM element geometry within the lens circle.
 */

export interface LensConfig {
  radius?: number;
  zoomScale?: number;
}

export class MeticInspectionLens {
  private root: HTMLElement | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private lensCircle: HTMLElement | null = null;
  private hudTag: HTMLElement | null = null;
  private toggleBtn: HTMLElement | null = null;
  private floatingHint: HTMLElement | null = null;

  private active: boolean = false;
  private persistentMode: boolean = false;
  private pointerX: number = 0;
  private pointerY: number = 0;
  private currentRadius: number = 130;
  private touchHoldTimer: number | null = null;
  private touchStartX: number = 0;
  private touchStartY: number = 0;
  private rafId: number | null = null;

  // Cached DOM inspection values to prevent layout thrashing
  private cachedRect: DOMRect | null = null;
  private cachedTag: string = '';
  private cachedClasses: string = '';
  private cachedComputed: { padding: string; margin: string; font: string } = {
    padding: '',
    margin: '',
    font: '',
  };
  private lastInspectTime: number = 0;

  constructor(config?: LensConfig) {
    if (config?.radius) {
      this.currentRadius = config.radius;
    }
  }

  public init() {
    this.root = document.getElementById('meticLensOverlayRoot');
    this.canvas = document.getElementById('meticLensCanvas') as HTMLCanvasElement | null;
    this.lensCircle = document.getElementById('meticLensCircle');
    this.hudTag = document.getElementById('meticLensHudTag');
    this.toggleBtn = document.getElementById('btnToggleInspect');
    this.floatingHint = document.getElementById('meticFloatingInspectHint');

    if (!this.root || !this.canvas || !this.lensCircle) {
      return;
    }

    this.ctx = this.canvas.getContext('2d');
    this.handleResize();

    window.addEventListener('resize', () => this.handleResize(), { passive: true });

    // Pointer events on window
    window.addEventListener('pointerdown', (e) => this.handlePointerDown(e), { passive: false });
    window.addEventListener('pointermove', (e) => this.handlePointerMove(e), { passive: true });
    window.addEventListener('pointerup', () => this.handlePointerUp(), { passive: true });
    window.addEventListener('pointercancel', () => this.handlePointerUp(), { passive: true });

    // Touch hold support for mobile without interfering with vertical scroll
    window.addEventListener('touchstart', (e) => this.handleTouchStart(e), { passive: true });
    window.addEventListener('touchmove', (e) => this.handleTouchMove(e), { passive: true });
    window.addEventListener('touchend', () => this.handleTouchEnd(), { passive: true });
    window.addEventListener('touchcancel', () => this.handleTouchEnd(), { passive: true });

    // Accessible keyboard shortcut: Press [I] to toggle persistent inspection mode
    window.addEventListener('keydown', (e) => {
      // Don't intercept when user is typing in textarea or input
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
      if (tag === 'input' || tag === 'textarea' || (e.target as HTMLElement)?.isContentEditable) {
        return;
      }
      if (e.key === 'i' || e.key === 'I') {
        e.preventDefault();
        this.togglePersistentMode();
      } else if (e.key === 'Escape' && (this.active || this.persistentMode)) {
        this.closeLens();
      }
    });

    // Toggle button in header / floating hint pill
    this.toggleBtn?.addEventListener('click', (e) => {
      e.preventDefault();
      this.togglePersistentMode();
    });

    this.floatingHint?.addEventListener('click', (e) => {
      e.preventDefault();
      this.togglePersistentMode();
    });
  }

  private handleResize() {
    if (!this.canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const width = window.innerWidth;
    const height = window.innerHeight;

    this.canvas.width = width * dpr;
    this.canvas.height = height * dpr;
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;

    if (this.ctx) {
      this.ctx.resetTransform?.();
      this.ctx.scale(dpr, dpr);
    }
  }

  private handlePointerDown(e: PointerEvent) {
    if (this.persistentMode) return;
    if (e.button !== 0) return; // Only primary mouse button

    // Do not trigger lens if user is interacting with form controls, buttons, links, or modals
    const target = e.target as HTMLElement | null;
    if (
      target?.closest('button') ||
      target?.closest('a') ||
      target?.closest('input') ||
      target?.closest('textarea') ||
      target?.closest('select') ||
      target?.closest('.modal-overlay') ||
      target?.closest('.metic-nav-links')
    ) {
      return;
    }

    this.pointerX = e.clientX;
    this.pointerY = e.clientY;

    if (e.pointerType === 'mouse') {
      this.openLens();
    }
  }

  private handlePointerMove(e: PointerEvent) {
    this.pointerX = e.clientX;
    this.pointerY = e.clientY;

    if (this.active) {
      this.updateInspectedElement();
    }
  }

  private handlePointerUp() {
    if (this.persistentMode) return;
    if (this.touchHoldTimer) {
      window.clearTimeout(this.touchHoldTimer);
      this.touchHoldTimer = null;
    }
    this.closeLens();
  }

  private handleTouchStart(e: TouchEvent) {
    if (this.persistentMode) return;
    if (e.touches.length !== 1) return;

    const touch = e.touches[0];
    const target = e.target as HTMLElement | null;
    if (
      target?.closest('button') ||
      target?.closest('a') ||
      target?.closest('input') ||
      target?.closest('textarea') ||
      target?.closest('select') ||
      target?.closest('.modal-overlay')
    ) {
      return;
    }

    this.touchStartX = touch.clientX;
    this.touchStartY = touch.clientY;
    this.pointerX = touch.clientX;
    this.pointerY = touch.clientY;

    // Hold 220ms to open lens on mobile (prevents accidental trigger while scrolling)
    this.touchHoldTimer = window.setTimeout(() => {
      this.openLens();
      if (typeof navigator.vibrate === 'function') {
        navigator.vibrate(15);
      }
    }, 220);
  }

  private handleTouchMove(e: TouchEvent) {
    if (e.touches.length !== 1) return;
    const touch = e.touches[0];

    // If movement exceeds 12px before lens opened, user is scrolling: cancel hold timer
    if (!this.active && this.touchHoldTimer) {
      const dx = Math.abs(touch.clientX - this.touchStartX);
      const dy = Math.abs(touch.clientY - this.touchStartY);
      if (dx > 12 || dy > 12) {
        window.clearTimeout(this.touchHoldTimer);
        this.touchHoldTimer = null;
      }
    }

    if (this.active) {
      this.pointerX = touch.clientX;
      this.pointerY = touch.clientY;
      this.updateInspectedElement();
    }
  }

  private handleTouchEnd() {
    if (this.touchHoldTimer) {
      window.clearTimeout(this.touchHoldTimer);
      this.touchHoldTimer = null;
    }
    if (!this.persistentMode) {
      this.closeLens();
    }
  }

  public togglePersistentMode() {
    this.persistentMode = !this.persistentMode;
    if (this.persistentMode) {
      if (this.pointerX === 0 && this.pointerY === 0) {
        this.pointerX = window.innerWidth / 2;
        this.pointerY = window.innerHeight / 2.5;
      }
      this.openLens();
      this.toggleBtn?.classList.add('active');
      this.floatingHint?.classList.add('active');
    } else {
      this.closeLens();
      this.toggleBtn?.classList.remove('active');
      this.floatingHint?.classList.remove('active');
    }
  }

  private openLens() {
    this.active = true;
    if (this.root) {
      this.root.classList.add('active');
      this.root.setAttribute('aria-hidden', 'false');
    }
    this.updateInspectedElement(true);
    this.startRenderLoop();
  }

  private closeLens() {
    if (this.persistentMode) return;
    this.active = false;
    if (this.root) {
      this.root.classList.remove('active');
      this.root.setAttribute('aria-hidden', 'true');
    }
    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    this.clearCanvas();
  }

  private clearCanvas() {
    if (!this.ctx || !this.canvas) return;
    this.ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
  }

  private startRenderLoop() {
    if (this.rafId !== null) return;
    const render = () => {
      if (!this.active) return;
      this.draw();
      this.rafId = requestAnimationFrame(render);
    };
    this.rafId = requestAnimationFrame(render);
  }

  /**
   * Throttled DOM inspection to retrieve actual bounding rectangle and computed styles
   * without triggering excessive reflows.
   */
  private updateInspectedElement(force: boolean = false) {
    const now = performance.now();
    if (!force && now - this.lastInspectTime < 60) {
      return;
    }
    this.lastInspectTime = now;

    // Temporarily ensure overlay doesn't block elementFromPoint
    const el = document.elementFromPoint(this.pointerX, this.pointerY) as HTMLElement | null;
    if (!el || el === this.root || this.root?.contains(el)) {
      return;
    }

    // Climb up to closest meaningful element
    const inspected =
      (el.closest('section, article, header, footer, nav, button, a, h1, h2, h3, p, .card, .metic-card, .metic-step-box, .metic-demo-sandbox') as HTMLElement) || el;

    this.cachedRect = inspected.getBoundingClientRect();
    this.cachedTag = inspected.tagName.toLowerCase();

    // Extract classes
    const classList = Array.from(inspected.classList)
      .filter((c) => !c.startsWith('metic-lens') && c !== 'active')
      .slice(0, 2);
    this.cachedClasses = classList.length > 0 ? `.${classList.join('.')}` : '';

    const comp = window.getComputedStyle(inspected);
    this.cachedComputed = {
      padding: `${comp.paddingTop} ${comp.paddingRight}`,
      margin: `${comp.marginTop} ${comp.marginRight}`,
      font: `${comp.fontFamily.split(',')[0].replace(/['"]/g, '')} ${comp.fontSize}`,
    };

    // Update HUD Tag Text
    if (this.hudTag) {
      const w = Math.round(this.cachedRect.width);
      const h = Math.round(this.cachedRect.height);
      const tagSpan = this.hudTag.querySelector('.hud-tag-el');
      if (tagSpan) {
        tagSpan.textContent = `<${this.cachedTag}${this.cachedClasses}>`;
      }
      const dimSpan = this.hudTag.querySelector('span:not(.hud-tag-el)');
      if (dimSpan) {
        dimSpan.textContent = `${w} × ${h}px`;
      }
    }
  }

  private draw() {
    if (!this.ctx || !this.canvas) return;
    const ctx = this.ctx;
    const width = window.innerWidth;
    const height = window.innerHeight;
    const x = this.pointerX;
    const y = this.pointerY;
    const r = this.currentRadius;

    ctx.clearRect(0, 0, width, height);

    // Position CSS lens circle & HUD Tag
    if (this.lensCircle) {
      this.lensCircle.style.transform = `translate3d(${x - r}px, ${y - r}px, 0)`;
      this.lensCircle.style.width = `${r * 2}px`;
      this.lensCircle.style.height = `${r * 2}px`;
    }

    if (this.hudTag) {
      this.hudTag.style.transform = `translate3d(${x - 90}px, ${y + r + 14}px, 0)`;
    }

    // Save context for clipping within circular lens
    ctx.save();
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.clip();

    // 1. Technical Inspection Background tint (warm off-white blueprint overlay)
    ctx.fillStyle = 'rgba(247, 246, 240, 0.94)';
    ctx.fillRect(x - r, y - r, r * 2, r * 2);

    // 2. Fine Layout Grid Lines (16px micro-grid)
    ctx.lineWidth = 0.5;
    ctx.strokeStyle = 'rgba(18, 19, 22, 0.08)';

    const startX = Math.floor((x - r) / 16) * 16;
    const endX = x + r;
    for (let gx = startX; gx <= endX; gx += 16) {
      ctx.beginPath();
      ctx.moveTo(gx, y - r);
      ctx.lineTo(gx, y + r);
      ctx.stroke();
    }

    const startY = Math.floor((y - r) / 16) * 16;
    const endY = y + r;
    for (let gy = startY; gy <= endY; gy += 16) {
      ctx.beginPath();
      ctx.moveTo(x - r, gy);
      ctx.lineTo(x + r, gy);
      ctx.stroke();
    }

    // Major 64px grid lines
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'rgba(220, 38, 38, 0.16)';
    const majorStartX = Math.floor((x - r) / 64) * 64;
    for (let gx = majorStartX; gx <= endX; gx += 64) {
      ctx.beginPath();
      ctx.moveTo(gx, y - r);
      ctx.lineTo(gx, y + r);
      ctx.stroke();
    }
    const majorStartY = Math.floor((y - r) / 64) * 64;
    for (let gy = majorStartY; gy <= endY; gy += 64) {
      ctx.beginPath();
      ctx.moveTo(x - r, gy);
      ctx.lineTo(x + r, gy);
      ctx.stroke();
    }

    // 3. Highlight currently inspected DOM element bounding box
    if (this.cachedRect) {
      const rect = this.cachedRect;
      const rx = rect.left;
      const ry = rect.top;
      const rw = rect.width;
      const rh = rect.height;

      // Container bounding box outline in architectural crimson
      ctx.strokeStyle = '#dc2626';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(rx, ry, rw, rh);

      // Soft container tint
      ctx.fillStyle = 'rgba(220, 38, 38, 0.06)';
      ctx.fillRect(rx, ry, rw, rh);

      // Caliper extension lines
      ctx.strokeStyle = 'rgba(220, 38, 38, 0.4)';
      ctx.lineWidth = 0.8;
      ctx.setLineDash([3, 3]);

      // Top dimension caliper
      ctx.beginPath();
      ctx.moveTo(rx, ry - 10);
      ctx.lineTo(rx + rw, ry - 10);
      ctx.moveTo(rx, ry - 15);
      ctx.lineTo(rx, ry - 5);
      ctx.moveTo(rx + rw, ry - 15);
      ctx.lineTo(rx + rw, ry - 5);
      ctx.stroke();

      // Left dimension caliper
      ctx.beginPath();
      ctx.moveTo(rx - 10, ry);
      ctx.lineTo(rx - 10, ry + rh);
      ctx.moveTo(rx - 15, ry);
      ctx.lineTo(rx - 5, ry);
      ctx.moveTo(rx - 15, ry + rh);
      ctx.lineTo(rx - 5, ry + rh);
      ctx.stroke();
      ctx.setLineDash([]);

      // Real DOM Measurement Badges (Width & Height)
      ctx.font = '600 10px "JetBrains Mono", monospace';
      ctx.fillStyle = '#dc2626';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      ctx.fillText(`${Math.round(rw)}px`, rx + rw / 2, ry - 12);

      ctx.save();
      ctx.translate(rx - 14, ry + rh / 2);
      ctx.rotate(-Math.PI / 2);
      ctx.fillText(`${Math.round(rh)}px`, 0, 0);
      ctx.restore();

      // Technical metadata tag
      ctx.fillStyle = '#121316';
      ctx.font = '700 11px "JetBrains Mono", monospace';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      const metaText = `<${this.cachedTag}${this.cachedClasses}>`;
      const textWidth = ctx.measureText(metaText).width;

      ctx.fillStyle = '#121316';
      ctx.fillRect(rx, ry, textWidth + 10, 18);
      ctx.fillStyle = '#ffffff';
      ctx.fillText(metaText, rx + 5, ry + 3);

      // Padding / font telemetry line
      ctx.fillStyle = 'rgba(18, 19, 22, 0.75)';
      ctx.font = '500 9px "JetBrains Mono", monospace';
      ctx.fillText(`PAD: ${this.cachedComputed.padding} | FONT: ${this.cachedComputed.font}`, rx + 4, ry + 22);
    }

    // 4. Alignment Crosshair / Reticle centered at pointer
    ctx.strokeStyle = '#121316';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x - r, y);
    ctx.lineTo(x + r, y);
    ctx.moveTo(x, y - r);
    ctx.lineTo(x, y + r);
    ctx.stroke();

    // Central reticle circle
    ctx.strokeStyle = '#dc2626';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(x, y, 14, 0, Math.PI * 2);
    ctx.stroke();

    // Center point dot
    ctx.fillStyle = '#dc2626';
    ctx.beginPath();
    ctx.arc(x, y, 2.5, 0, Math.PI * 2);
    ctx.fill();

    // Live Coordinate Tag near reticle center
    ctx.font = '600 9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#121316';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'bottom';
    ctx.fillText(`X:${Math.round(x)} Y:${Math.round(y)}`, x + 18, y - 6);

    // Degree Ticks on Reticle Perimeter (0, 90, 180, 270)
    ctx.strokeStyle = '#121316';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x, y - r);
    ctx.lineTo(x, y - r + 8);
    ctx.moveTo(x, y + r);
    ctx.lineTo(x, y + r - 8);
    ctx.moveTo(x - r, y);
    ctx.lineTo(x - r + 8, y);
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + r - 8, y);
    ctx.stroke();

    ctx.restore(); // Restore clipping
  }
}

export const meticLens = new MeticInspectionLens();
