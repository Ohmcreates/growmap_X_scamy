import { AuthService } from '../services/authService.js';

export function updateLandingAuthState(): void {
  const user = AuthService.getUser();
  const guestGroup = document.getElementById('landingGuestAuthCluster');
  const userGroup = document.getElementById('landingUserAuthCluster');

  const heroCta = document.getElementById('heroPrimaryCta');
  const heroCtaText = document.getElementById('heroPrimaryCtaText');
  const finalCta = document.getElementById('landingFinalCta');
  const finalCtaText = document.getElementById('landingFinalCtaText');

  const footerLinkScanner = document.getElementById('footerLinkScanner');
  const footerLinkUrl = document.getElementById('footerLinkUrl');
  const footerLinkOcr = document.getElementById('footerLinkOcr');

  if (user && AuthService.isAuthenticated()) {
    // USER IS SIGNED IN:
    // Hide guest buttons, show direct workspace navigation with ZERO user personal data displayed on landing page
    if (guestGroup) guestGroup.style.display = 'none';
    if (userGroup) userGroup.style.display = 'flex';

    if (heroCta) {
      heroCta.setAttribute('href', '/workspace');
      heroCta.setAttribute('data-route-to', 'workspace');
    }
    if (heroCtaText) heroCtaText.textContent = 'Open Scanner Workspace';

    if (finalCta) {
      finalCta.setAttribute('href', '/workspace');
      finalCta.setAttribute('data-route-to', 'workspace');
    }
    if (finalCtaText) finalCtaText.textContent = 'Open Scanner Workspace';

    [footerLinkScanner, footerLinkUrl, footerLinkOcr].forEach((link) => {
      if (link) {
        link.setAttribute('href', '/workspace');
        link.setAttribute('data-route-to', 'workspace');
      }
    });
  } else {
    // USER IS GUEST (NOT SIGNED IN):
    // Show Sign In and Sign Up options
    if (guestGroup) guestGroup.style.display = 'flex';
    if (userGroup) userGroup.style.display = 'none';

    if (heroCta) {
      heroCta.setAttribute('href', '/workspace');
      heroCta.setAttribute('data-route-to', 'workspace');
    }
    if (heroCtaText) heroCtaText.textContent = 'Check a Message (Guest)';

    if (finalCta) {
      finalCta.setAttribute('href', '/workspace');
      finalCta.setAttribute('data-route-to', 'workspace');
    }
    if (finalCtaText) finalCtaText.textContent = 'Scan a Suspicious Message';

    if (footerLinkScanner) {
      footerLinkScanner.setAttribute('href', '/workspace');
      footerLinkScanner.setAttribute('data-route-to', 'workspace');
    }
    [footerLinkUrl, footerLinkOcr].forEach((link) => {
      if (link) {
        link.setAttribute('href', '/login');
        link.setAttribute('data-route-to', 'login');
      }
    });
  }
}

export function initLandingAuth(): void {
  updateLandingAuthState();
  AuthService.verifySession().then(() => {
    updateLandingAuthState();
  });
  window.addEventListener('auth-state-changed', () => {
    updateLandingAuthState();
  });
}
