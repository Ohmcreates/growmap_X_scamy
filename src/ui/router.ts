/**
 * Scam Spotter — Client-Side Hash Router
 * Orchestrates seamless transitions between:
 *  - Editorial Landing Page (#landing)
 *  - Authentication View (#login)
 *  - Main Scanner Workspace (#workspace)
 */

export type AppRoute = 'landing' | 'login' | 'workspace';

const APP_ROUTES = new Set(['landing', 'login', 'workspace', 'app', 'auth', 'signup']);

export class AppRouter {
  private currentRoute: AppRoute = 'landing';
  private landingView: HTMLElement | null = null;
  private authView: HTMLElement | null = null;
  private appWorkspaceView: HTMLElement | null = null;

  constructor() {
    this.handleHashChange = this.handleHashChange.bind(this);
  }

  public init() {
    this.landingView = document.getElementById('landingView');
    this.authView = document.getElementById('authView');
    this.appWorkspaceView = document.getElementById('appWorkspaceView');

    window.addEventListener('hashchange', this.handleHashChange);

    // Mobile nav toggle
    const menuToggle = document.querySelector('.metic-menu-toggle');
    const navLinks = document.getElementById('meticNavLinks');
    menuToggle?.addEventListener('click', (e) => {
      e.stopPropagation();
      navLinks?.classList.toggle('mobile-open');
    });

    // Delegate clicks for routing and anchor links
    document.addEventListener('click', (e) => {
      // 1. Check data-route-to
      const target = (e.target as HTMLElement).closest('[data-route-to]') as HTMLElement | null;
      if (target) {
        const route = target.getAttribute('data-route-to') as AppRoute;
        if (route && (route === 'landing' || route === 'login' || route === 'workspace')) {
          e.preventDefault();
          this.navigate(route);
          return;
        }
      }

      // 2. Check anchor links (e.g. #how-it-works, #features, etc.)
      const anchor = (e.target as HTMLElement).closest('.metic-nav-links a, a[href^="#"]') as HTMLAnchorElement | null;
      if (anchor) {
        const href = anchor.getAttribute('href');
        if (href && href.startsWith('#') && href.length > 1) {
          const targetId = href.replace(/^#\/?/, '').toLowerCase();
          if (APP_ROUTES.has(targetId)) return;

          const targetEl = document.getElementById(targetId);
          if (targetEl) {
            e.preventDefault();
            navLinks?.classList.remove('mobile-open');

            if (this.currentRoute !== 'landing') {
              this.currentRoute = 'landing';
              this.render(false);
              setTimeout(() => {
                targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
                history.pushState(null, '', `#${targetId}`);
              }, 80);
            } else {
              targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
              history.pushState(null, '', `#${targetId}`);
            }
          }
        }
      }
    });

    // Check initial hash
    const initialHash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (initialHash === 'workspace' || initialHash === 'app') {
      this.navigate('workspace');
    } else if (initialHash === 'login' || initialHash === 'auth' || initialHash === 'signup') {
      this.navigate('login');
      if (initialHash === 'signup') {
        setTimeout(() => {
          document.getElementById('authViewTabSignUp')?.click();
        }, 50);
      }
    } else if (initialHash && !APP_ROUTES.has(initialHash)) {
      // Section anchor on landing page
      this.navigate('landing', false);
      setTimeout(() => {
        const el = document.getElementById(initialHash);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 150);
    } else {
      this.navigate('landing', true);
    }

    this.initScrollspy();
  }

  private initScrollspy() {
    const sectionConfigs = [
      { id: 'heroSection', navTarget: 'heroSection' },
      { id: 'build', navTarget: 'build' },
      { id: 'features', navTarget: 'features' },
      { id: 'how-it-works', navTarget: 'how-it-works' },
      { id: 'live-demo', navTarget: 'live-demo' },
      { id: 'link-security', navTarget: 'link-security' },
      { id: 'trust', navTarget: 'trust' },
    ];

    let ticking = false;

    const onScroll = () => {
      if (this.currentRoute !== 'landing') return;
      if (!ticking) {
        window.requestAnimationFrame(() => {
          const scrollY = window.scrollY || window.pageYOffset;
          const headerOffset = 140;
          let activeTarget = 'heroSection';

          for (const item of sectionConfigs) {
            const el = document.getElementById(item.id);
            if (el) {
              const top = el.offsetTop - headerOffset;
              if (scrollY >= top) {
                activeTarget = item.navTarget;
              }
            }
          }

          // Near bottom of page: activate last section
          if (window.innerHeight + scrollY >= document.body.offsetHeight - 80) {
            activeTarget = 'trust';
          }

          const navItems = document.querySelectorAll('.nav-section-item');
          navItems.forEach((navItem) => {
            const target = navItem.getAttribute('data-section-target');
            if (target === activeTarget) {
              navItem.classList.add('active');
            } else {
              navItem.classList.remove('active');
            }
          });

          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    setTimeout(onScroll, 100);
  }

  public navigate(route: AppRoute, scrollToTop: boolean = true) {
    this.currentRoute = route;
    if (window.location.hash.replace(/^#\/?/, '').toLowerCase() !== route) {
      window.location.hash = `#${route}`;
    }
    this.render(scrollToTop);
  }

  public getRoute(): AppRoute {
    return this.currentRoute;
  }

  private handleHashChange() {
    const hash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (hash === 'workspace' || hash === 'app') {
      this.currentRoute = 'workspace';
      this.render(true);
      return;
    }
    if (hash === 'login' || hash === 'auth' || hash === 'signup') {
      this.currentRoute = 'login';
      this.render(true);
      if (hash === 'signup') {
        setTimeout(() => {
          document.getElementById('authViewTabSignUp')?.click();
        }, 50);
      }
      return;
    }

    // Check if hash points to a landing section element
    if (hash && hash !== 'landing') {
      const targetEl = document.getElementById(hash);
      if (targetEl) {
        const wasNotLanding = this.currentRoute !== 'landing';
        this.currentRoute = 'landing';
        if (wasNotLanding) {
          this.render(false);
          setTimeout(() => {
            targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }, 80);
        } else {
          targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        return;
      }
    }

    this.currentRoute = 'landing';
    this.render(true);
  }

  private render(scrollToTop: boolean = true) {
    if (!this.landingView || !this.authView || !this.appWorkspaceView) {
      this.landingView = document.getElementById('landingView');
      this.authView = document.getElementById('authView');
      this.appWorkspaceView = document.getElementById('appWorkspaceView');
    }

    if (!this.landingView || !this.authView || !this.appWorkspaceView) return;

    const magnifier = document.getElementById('draggableMagnifier');
    const dockBar = document.getElementById('magnifierDockBar');
    const cornerToggle = document.getElementById('btnMagnifierCornerToggle');

    const showMagnifier = shouldDisplayMagnifier(this.currentRoute);
    if (!showMagnifier) {
      if (magnifier) magnifier.style.display = 'none';
      if (dockBar) dockBar.style.display = 'none';
      if (cornerToggle) cornerToggle.style.display = 'none';
    } else {
      if (cornerToggle) cornerToggle.style.display = 'flex';
      const isOff = cornerToggle?.classList.contains('is-off') || cornerToggle?.classList.contains('minimized');
      if (magnifier) magnifier.style.display = isOff ? 'none' : 'block';
      if (dockBar) dockBar.style.display = isOff ? 'none' : 'flex';
    }

    if (this.currentRoute === 'landing') {
      this.landingView.style.display = 'block';
      this.landingView.classList.add('active');
      this.authView.style.display = 'none';
      this.authView.classList.remove('active');
      this.appWorkspaceView.style.display = 'none';
      this.appWorkspaceView.classList.remove('active');
      if (scrollToTop) {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } else if (this.currentRoute === 'login') {
      this.landingView.style.display = 'none';
      this.landingView.classList.remove('active');
      this.authView.style.display = 'flex';
      this.authView.classList.add('active');
      this.appWorkspaceView.style.display = 'none';
      this.appWorkspaceView.classList.remove('active');
      if (scrollToTop) {
        window.scrollTo(0, 0);
      }
    } else {
      // Main website (#workspace): remove the magnifying glass and dock bar
      this.landingView.style.display = 'none';
      this.landingView.classList.remove('active');
      this.authView.style.display = 'none';
      this.authView.classList.remove('active');
      this.appWorkspaceView.style.display = 'block';
      this.appWorkspaceView.classList.add('active');
      if (scrollToTop) {
        window.scrollTo(0, 0);
      }
    }
  }
}

export function shouldDisplayMagnifier(route: AppRoute): boolean {
  return route === 'landing';
}

export const router = new AppRouter();
