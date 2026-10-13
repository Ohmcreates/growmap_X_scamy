/**
 * Scam Spotter — Progressive Page Construction
 *
 * Demonstrates how Scam Spotter works through 7 progressive architectural stages:
 *  1. Alignment line (Datum axis)
 *  2. Page grid (12-column isometric blueprint)
 *  3. Content layout (Container boundaries & spatial rhythm)
 *  4. Typography & visual hierarchy (Editorial serif + technical monospace)
 *  5. Red-and-neutral color system (Warm off-white, near-black, restrained crimson)
 *  6. Scam detection interface (Rule indicators, weights & evidence tokens)
 *  7. Finished Scam Spotter experience (Complete handcrafted forensics platform)
 */

export interface BuildStage {
  step: number;
  id: string;
  title: string;
  subtitle: string;
  description: string;
  spec: string;
}

export const BUILD_STAGES: BuildStage[] = [
  {
    step: 1,
    id: 'datum',
    title: 'The Alignment Line',
    subtitle: 'Zero-tolerance horizontal datum',
    description:
      'Every fraud analysis begins with a strict mathematical axis. No ambiguous heuristics; clear alignment ensures unambiguous boundary definitions between benign conversational prose and malicious coercion.',
    spec: 'ALIGN: X-AXIS 0.00° // TOLERANCE: ±0.00px // SPEC: DETERMINISTIC_DATUM',
  },
  {
    step: 2,
    id: 'grid',
    title: 'The Page Grid',
    subtitle: '12-column architectural matrix',
    description:
      'Rigid structural scaffolding divides raw input messages into structured tokens. Grid columns balance whitespace and data density, making critical security warnings immediately legible under stress.',
    spec: 'GRID: 12-COL MODULAR // GUTTER: 24px // BASELINE: 4px RETICLE',
  },
  {
    step: 3,
    id: 'layout',
    title: 'The Content Layout',
    subtitle: 'Boundary containment & spatial hierarchy',
    description:
      'Individual cards isolate discrete analysis signals: input buffer, token highlight preview, risk meter, and step-by-step containment instructions. Clear boundaries prevent cognitive fatigue.',
    spec: 'CONTAINERS: 3-ZONE SPATIAL // RATIO: 1.618 GOLDEN SECTION // ELEVATION: 0px FLAT',
  },
  {
    step: 4,
    id: 'typography',
    title: 'Typography & Hierarchy',
    subtitle: 'Editorial serif paired with technical mono',
    description:
      'Editorial serif establishes calm, deliberate authority, while JetBrains Mono renders raw evidence indicators and byte measurements with precision. Typographic scale guides the reader naturally.',
    spec: 'DISPLAY: NEWSREADER SERIF // BODY: PLUS JAKARTA SANS // TELEMETRY: JETBRAINS MONO',
  },
  {
    step: 5,
    id: 'color',
    title: 'The Red & Neutral System',
    subtitle: 'Warm off-white, near-black, and restrained crimson',
    description:
      'Avoiding noisy gradients and synthetic neon cards. The warm off-white canvas provides calm clarity, reserving security crimson strictly for confirmed fraud threats and actionable alarms.',
    spec: 'CANVAS: #FBFBFA // INK: #121316 // ACCENT: #DC2626 // CONTRAST: 12.8:1 AAA',
  },
  {
    step: 6,
    id: 'engine',
    title: 'Scam Detection Interface',
    subtitle: 'Transparent rules & weighted evidence',
    description:
      'Transparent rule weights (+20 Urgency, +15 Threat, +25 Link, +40 OTP) appear alongside highlighted phrases. Nothing is hidden inside opaque neural network hallucinations.',
    spec: 'RULES: 16 CATEGORIES // WEIGHTS: ARITHMETIC SUM // CAPPING: CORRELATED GROUPS',
  },
  {
    step: 7,
    id: 'finished',
    title: 'The Finished Experience',
    subtitle: 'Complete production fraud forensics',
    description:
      'The finished Scam Spotter workspace brings together client-side message scanning, URL forensic decomposition, OCR screenshot extraction, and actionable verification steps.',
    spec: 'STATUS: PRODUCTION-READY // RUNTIME: CLIENT-SIDE // PRIVACY: ZERO DATA EXFIL',
  },
];

export class ProgressiveBuildController {
  private currentStage: number = 1;
  private container: HTMLElement | null = null;
  private stageDisplayCanvas: HTMLElement | null = null;
  private stageStepPills: NodeListOf<HTMLElement> | null = null;
  private stageTitleEl: HTMLElement | null = null;
  private stageSubEl: HTMLElement | null = null;
  private stageDescEl: HTMLElement | null = null;
  private stageSpecEl: HTMLElement | null = null;
  private stageCounterEl: HTMLElement | null = null;
  private btnPrev: HTMLElement | null = null;
  private btnNext: HTMLElement | null = null;

  public init() {
    this.container = document.getElementById('progressiveBuildSection');
    if (!this.container) return;

    this.stageDisplayCanvas = document.getElementById('buildStageDisplayCanvas');
    this.stageStepPills = document.querySelectorAll('.metic-stage-pill');
    this.stageTitleEl = document.getElementById('buildStageTitle');
    this.stageSubEl = document.getElementById('buildStageSubtitle');
    this.stageDescEl = document.getElementById('buildStageDescription');
    this.stageSpecEl = document.getElementById('buildStageSpec');
    this.stageCounterEl = document.getElementById('buildStageCounter');
    this.btnPrev = document.getElementById('btnBuildPrev');
    this.btnNext = document.getElementById('btnBuildNext');

    // Stage navigation clicks
    this.stageStepPills.forEach((pill) => {
      pill.addEventListener('click', () => {
        const step = parseInt(pill.getAttribute('data-stage') || '1', 10);
        this.goToStage(step);
      });
    });

    this.btnPrev?.addEventListener('click', () => {
      this.goToStage(this.currentStage - 1);
    });

    this.btnNext?.addEventListener('click', () => {
      this.goToStage(this.currentStage + 1);
    });

    // IntersectionObserver for scroll-driven progression
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              const ratio = entry.intersectionRatio;
              const targetStage = Math.min(
                7,
                Math.max(1, Math.round(ratio * 7))
              );
              if (this.currentStage === 1 && targetStage > 1) {
                this.goToStage(targetStage);
              }
            }
          });
        },
        { threshold: [0.15, 0.35, 0.55, 0.75, 0.9] }
      );

      observer.observe(this.container);
    }

    this.renderStage();
  }

  public goToStage(stageNum: number) {
    if (stageNum < 1) stageNum = 1;
    if (stageNum > 7) stageNum = 7;
    this.currentStage = stageNum;
    this.renderStage();
  }

  private renderStage() {
    const stage = BUILD_STAGES.find((s) => s.step === this.currentStage) || BUILD_STAGES[0];

    // Update Stage Canvas classes
    if (this.stageDisplayCanvas) {
      this.stageDisplayCanvas.className = `metic-build-canvas stage-${this.currentStage}`;
    }

    // Update Pills
    if (this.stageStepPills) {
      this.stageStepPills.forEach((pill) => {
        const step = parseInt(pill.getAttribute('data-stage') || '1', 10);
        if (step === this.currentStage) {
          pill.classList.add('active');
          pill.setAttribute('aria-selected', 'true');
        } else {
          pill.classList.remove('active');
          pill.setAttribute('aria-selected', 'false');
        }
      });
    }

    // Update Text
    if (this.stageTitleEl) this.stageTitleEl.textContent = stage.title;
    if (this.stageSubEl) this.stageSubEl.textContent = stage.subtitle;
    if (this.stageDescEl) this.stageDescEl.textContent = stage.description;
    if (this.stageSpecEl) this.stageSpecEl.textContent = stage.spec;
    if (this.stageCounterEl) this.stageCounterEl.textContent = `0${stage.step} / 07`;

    // Disable / Enable Prev / Next buttons
    if (this.btnPrev) {
      this.btnPrev.toggleAttribute('disabled', this.currentStage === 1);
    }
    if (this.btnNext) {
      this.btnNext.toggleAttribute('disabled', this.currentStage === 7);
    }
  }
}

export const progressiveBuild = new ProgressiveBuildController();
