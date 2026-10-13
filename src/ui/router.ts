/**
 * Scam Spotter — Client-Side Hash Router
 * Orchestrates seamless transitions between:
 *  - Editorial Landing Page (#landing)
 *  - Authentication View (#login)
 *  - Main Scanner Workspace (#workspace)
 */

export type AppRoute = 'landing' | 'login' | 'workspace';

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

    // Delegate clicks for elements with data-route-to
    document.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest('[data-route-to]') as HTMLElement | null;
      if (target) {
        const route = target.getAttribute('data-route-to') as AppRoute;
        if (route && (route === 'landing' || route === 'login' || route === 'workspace')) {
          e.preventDefault();
          this.navigate(route);
        }
      }
    });

    // Check initial hash
    const initialHash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (initialHash === 'workspace' || initialHash === 'app') {
      this.navigate('workspace');
    } else if (initialHash === 'login' || initialHash === 'auth') {
      this.navigate('login');
    } else {
      this.navigate('landing');
    }
  }

  public navigate(route: AppRoute) {
    this.currentRoute = route;
    window.location.hash = `#${route}`;
    this.render();
  }

  public getRoute(): AppRoute {
    return this.currentRoute;
  }

  private handleHashChange() {
    const hash = window.location.hash.replace(/^#\/?/, '').toLowerCase();
    if (hash === 'workspace' || hash === 'app') {
      this.currentRoute = 'workspace';
    } else if (hash === 'login' || hash === 'auth') {
      this.currentRoute = 'login';
    } else {
      this.currentRoute = 'landing';
    }
    this.render();
  }

  private render() {
    if (!this.landingView || !this.authView || !this.appWorkspaceView) {
      this.landingView = document.getElementById('landingView');
      this.authView = document.getElementById('authView');
      this.appWorkspaceView = document.getElementById('appWorkspaceView');
    }

    if (!this.landingView || !this.authView || !this.appWorkspaceView) return;

    if (this.currentRoute === 'landing') {
      this.landingView.style.display = 'block';
      this.landingView.classList.add('active');
      this.authView.style.display = 'none';
      this.authView.classList.remove('active');
      this.appWorkspaceView.style.display = 'none';
      this.appWorkspaceView.classList.remove('active');
      window.scrollTo(0, 0);
    } else if (this.currentRoute === 'login') {
      this.landingView.style.display = 'none';
      this.landingView.classList.remove('active');
      this.authView.style.display = 'flex';
      this.authView.classList.add('active');
      this.appWorkspaceView.style.display = 'none';
      this.appWorkspaceView.classList.remove('active');
      window.scrollTo(0, 0);
    } else {
      this.landingView.style.display = 'none';
      this.landingView.classList.remove('active');
      this.authView.style.display = 'none';
      this.authView.classList.remove('active');
      this.appWorkspaceView.style.display = 'block';
      this.appWorkspaceView.classList.add('active');
      window.scrollTo(0, 0);
    }
  }
}

export const router = new AppRouter();
