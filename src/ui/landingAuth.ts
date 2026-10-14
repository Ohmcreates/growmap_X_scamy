import { AuthService } from '../services/authService.js';

export function updateLandingAuthState(): void {
  const user = AuthService.getUser();
  const guestGroup = document.getElementById('landingGuestAuthCluster');
  const userGroup = document.getElementById('landingUserAuthCluster');
  const userName = document.getElementById('landingUserName');
  const userAvatar = document.getElementById('landingUserAvatar');

  const heroCta = document.getElementById('heroPrimaryCta');
  const heroCtaText = document.getElementById('heroPrimaryCtaText');
  const finalCta = document.getElementById('landingFinalCta');
  const finalCtaText = document.getElementById('landingFinalCtaText');

  const footerLinkScanner = document.getElementById('footerLinkScanner');
  const footerLinkUrl = document.getElementById('footerLinkUrl');
  const footerLinkOcr = document.getElementById('footerLinkOcr');

  if (user && AuthService.isAuthenticated()) {
    // USER IS SIGNED IN:
    // Hide Sign In / Sign Up, show user greeting and direct workspace navigation
    if (guestGroup) guestGroup.style.display = 'none';
    if (userGroup) userGroup.style.display = 'flex';
    if (userName) userName.textContent = user.name.split(' ')[0] || user.name;
    if (userAvatar) userAvatar.textContent = (user.name[0] || 'U').toUpperCase();

    if (heroCta) {
      heroCta.setAttribute('href', '#workspace');
      heroCta.setAttribute('data-route-to', 'workspace');
    }
    if (heroCtaText) heroCtaText.textContent = 'Open Scanner Workspace';

    if (finalCta) {
      finalCta.setAttribute('href', '#workspace');
      finalCta.setAttribute('data-route-to', 'workspace');
    }
    if (finalCtaText) finalCtaText.textContent = 'Open Scanner Workspace';

    [footerLinkScanner, footerLinkUrl, footerLinkOcr].forEach((link) => {
      if (link) {
        link.setAttribute('href', '#workspace');
        link.setAttribute('data-route-to', 'workspace');
      }
    });
  } else {
    // USER IS GUEST (NOT SIGNED IN):
    // Show Sign In and Sign Up options
    if (guestGroup) guestGroup.style.display = 'flex';
    if (userGroup) userGroup.style.display = 'none';

    if (heroCta) {
      heroCta.setAttribute('href', '#login');
      heroCta.setAttribute('data-route-to', 'login');
    }
    if (heroCtaText) heroCtaText.textContent = 'Check a Message';

    if (finalCta) {
      finalCta.setAttribute('href', '#login');
      finalCta.setAttribute('data-route-to', 'login');
    }
    if (finalCtaText) finalCtaText.textContent = 'Scan a Suspicious Message';

    [footerLinkScanner, footerLinkUrl, footerLinkOcr].forEach((link) => {
      if (link) {
        link.setAttribute('href', '#login');
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
