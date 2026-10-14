/**
 * Scam Spotter — Client-Side Router
 * Orchestrates seamless transitions between:
 *  - Editorial Landing Page (/)
 *  - Authentication View (/login)
 *  - Main Scanner Workspace (/workspace)
 *
 * Enforces strict authentication security: unauthenticated users cannot access /workspace.
 */

import { AuthService } from '../services/authService.js';

export type AppRoute = 'landing' | 'login' | 'workspace';

const APP_ROUTES = new Set(['landing', 'login', 'workspace', 'app', 'auth', 'signup']);

export class AppRouter {
  private currentRoute: AppRoute = 'landing';
  private landingView: HTMLElement | null = null;
  private authView: HTMLElement | null = null;
  private appWorkspaceView: HTMLElement | null = null;

  constructor() {
    this.handleLocationChange = this.handleLocationChange.bind(this);
  }

  public init() {
    this.landingView = document.getElementById('landingView');
    this.authView = document.getElementById('authView');
    this.appWorkspaceView = document.getElementById('appWorkspaceView');

    window.addEventListener('popstate', this.handleLocationChange);
    window.addEventListener('hashchange', this.handleLocationChange);

    // Watch auth changes: if user logs out while in workspace, kick them out to /login
    window.addEventListener('auth-state-changed', () => {
      if (this.currentRoute === 'workspace' && !AuthService.isAuthenticated()) {
        this.navigate('login');
      }
    });

    // Mobile nav toggle
    const menuToggle = document.querySelector('.metic-menu-toggle');
    const navLinks = document.getElementById('meticNavLinks');
    menuToggle?.addEventListener('click', (e) => {
      e.stopPropagation();
      navLinks?.classList.toggle('mobile-open');
    });

    // Delegate clicks for routing and anchor links
    document.addEventListener('click', (e) => {
      // 1. Check data-route-to or clean path links
      const target = (e.target as HTMLElement).closest('[data-route-to], a[href="/workspace"], a[href="/login"], a[href="/"]') as HTMLElement | null;
      if (target) {
        let route = target.getAttribute('data-route-to') as AppRoute | null;
        if (!route) {
          const href = target.getAttribute('href');
          if (href === '/workspace') route = 'workspace';
          else if (href === '/login') route = 'login';
          else if (href === '/') route = 'landing';
        }

        if (route && (route === 'landing' || route === 'login' || route === 'workspace')) {
          e.preventDefault();
          this.navigate(route);
          return;
        }
      }

      // 2. Check anchor links (e.g. #heroSection, #how-it-works, #features, etc.)
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
              this.updateUrl('landing');
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

    // Check initial route from URL
    const { route, sectionId } = this.getRouteFromLocation();
    if (sectionId) {
      this.navigate('landing', false);
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 150);
    } else {
      this.navigate(route, true);
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
    // SECURITY GUARD: If user attempts to enter workspace without login, block access!
    if (route === 'workspace') {
      if (!AuthService.isAuthenticated()) {
        this.currentRoute = 'login';
        this.updateUrl('login');
        this.render(true);

        setTimeout(() => {
          const alertBox = document.getElementById('authViewAlert');
          if (alertBox) {
            alertBox.textContent = '🔒 Access Restricted: Please sign in to access the scanner workspace.';
            alertBox.style.display = 'block';
          }
        }, 100);
        return;
      }
    }

    this.currentRoute = route;
    this.updateUrl(route);
    this.render(scrollToTop);
  }

  public getRoute(): AppRoute {
    return this.currentRoute;
  }

  private updateUrl(route: AppRoute) {
    const targetPath = route === 'landing' ? '/' : `/${route}`;
    try {
      if (window.location.pathname !== targetPath) {
        window.history.pushState(null, '', targetPath);
      }
    } catch {
      window.location.hash = targetPath.replace(/^\//, '#');
    }
  }

  private getRouteFromLocation(): { route: AppRoute; sectionId?: string } {
    const pathname = window.location.pathname.replace(/^\//, '').toLowerCase();
    if (pathname === 'workspace' || pathname === 'app') return { route: 'workspace' };
    if (pathname === 'login' || pathname === 'auth' || pathname === 'signup') return { route: 'login' };

    const hash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (hash === 'workspace' || hash === 'app') return { route: 'workspace' };
    if (hash === 'login' || hash === 'auth' || hash === 'signup') return { route: 'login' };
    if (hash && hash !== 'landing') return { route: 'landing', sectionId: hash };

    return { route: 'landing' };
  }

  private handleLocationChange() {
    const { route, sectionId } = this.getRouteFromLocation();

    if (sectionId) {
      const targetEl = document.getElementById(sectionId);
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

    this.navigate(route, true);
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
      // Main website (/workspace): remove the magnifying glass and dock bar
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
