import { AuthService } from '../services/authService.js';
import { router } from './router.js';

export type AuthViewMode = 'signin' | 'signup';

export class AuthViewController {
  private currentMode: AuthViewMode = 'signin';

  private tabSignIn: HTMLButtonElement | null = null;
  private tabSignUp: HTMLButtonElement | null = null;
  private editorialTag: HTMLElement | null = null;
  private title: HTMLElement | null = null;
  private subtitle: HTMLElement | null = null;
  private alertBox: HTMLElement | null = null;

  private formSignIn: HTMLFormElement | null = null;
  private inputSignInEmail: HTMLInputElement | null = null;
  private inputSignInPassword: HTMLInputElement | null = null;
  private btnSubmitSignIn: HTMLButtonElement | null = null;

  private formSignUp: HTMLFormElement | null = null;
  private inputSignUpName: HTMLInputElement | null = null;
  private inputSignUpEmail: HTMLInputElement | null = null;
  private inputSignUpPassword: HTMLInputElement | null = null;
  private btnSubmitSignUp: HTMLButtonElement | null = null;

  private toggleHintText: HTMLElement | null = null;
  private btnToggleMode: HTMLButtonElement | null = null;
  private btnDemo: HTMLButtonElement | null = null;

  public init(): void {
    this.tabSignIn = document.getElementById('authViewTabSignIn') as HTMLButtonElement | null;
    this.tabSignUp = document.getElementById('authViewTabSignUp') as HTMLButtonElement | null;
    this.editorialTag = document.getElementById('authViewEditorialTag');
    this.title = document.getElementById('authViewTitle');
    this.subtitle = document.getElementById('authViewSubtitle');
    this.alertBox = document.getElementById('authViewAlert');

    this.formSignIn = document.getElementById('authFormSignIn') as HTMLFormElement | null;
    this.inputSignInEmail = document.getElementById('authSignInEmail') as HTMLInputElement | null;
    this.inputSignInPassword = document.getElementById('authSignInPassword') as HTMLInputElement | null;
    this.btnSubmitSignIn = document.getElementById('btnSubmitSignIn') as HTMLButtonElement | null;

    this.formSignUp = document.getElementById('authFormSignUp') as HTMLFormElement | null;
    this.inputSignUpName = document.getElementById('authSignUpName') as HTMLInputElement | null;
    this.inputSignUpEmail = document.getElementById('authSignUpEmail') as HTMLInputElement | null;
    this.inputSignUpPassword = document.getElementById('authSignUpPassword') as HTMLInputElement | null;
    this.btnSubmitSignUp = document.getElementById('btnSubmitSignUp') as HTMLButtonElement | null;

    this.toggleHintText = document.getElementById('authToggleHintText');
    this.btnToggleMode = document.getElementById('btnToggleAuthMode') as HTMLButtonElement | null;
    this.btnDemo = document.getElementById('btnAuthDemo') as HTMLButtonElement | null;

    this.tabSignIn?.addEventListener('click', () => this.setMode('signin'));
    this.tabSignUp?.addEventListener('click', () => this.setMode('signup'));

    this.btnToggleMode?.addEventListener('click', () => {
      this.setMode(this.currentMode === 'signin' ? 'signup' : 'signin');
    });

    this.btnDemo?.addEventListener('click', () => {
      AuthService.setGuestMode();
      router.navigate('workspace');
    });

    document.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest('[data-auth-mode]') as HTMLElement | null;
      if (target) {
        const mode = target.getAttribute('data-auth-mode');
        if (mode === 'signup' || mode === 'signin') {
          this.setMode(mode as AuthViewMode);
        }
      }
    });

    this.formSignIn?.addEventListener('submit', (e) => this.handleSignIn(e));
    this.formSignUp?.addEventListener('submit', (e) => this.handleSignUp(e));
  }

  public setMode(mode: AuthViewMode): void {
    this.currentMode = mode;
    this.clearAlert();

    if (mode === 'signin') {
      this.tabSignIn?.classList.add('active');
      this.tabSignUp?.classList.remove('active');
      this.tabSignIn?.setAttribute('aria-selected', 'true');
      this.tabSignUp?.setAttribute('aria-selected', 'false');

      if (this.editorialTag) this.editorialTag.textContent = '01 // ACCESS CONTROL';
      if (this.title) this.title.textContent = 'Analyst Sign In';
      if (this.subtitle) {
        this.subtitle.textContent = 'Sign in to access your scam detection history & analysis workspace.';
      }

      if (this.formSignIn) this.formSignIn.style.display = 'flex';
      if (this.formSignUp) this.formSignUp.style.display = 'none';

      if (this.toggleHintText) this.toggleHintText.textContent = "Don't have an account?";
      if (this.btnToggleMode) this.btnToggleMode.textContent = 'Create an account';
      this.inputSignInEmail?.focus();
    } else {
      this.tabSignUp?.classList.add('active');
      this.tabSignIn?.classList.remove('active');
      this.tabSignUp?.setAttribute('aria-selected', 'true');
      this.tabSignIn?.setAttribute('aria-selected', 'false');

      if (this.editorialTag) this.editorialTag.textContent = '01 // REGISTRATION';
      if (this.title) this.title.textContent = 'Create Analyst Account';
      if (this.subtitle) {
        this.subtitle.textContent = 'Register to track scans, access threat histories & synchronize sessions.';
      }

      if (this.formSignUp) this.formSignUp.style.display = 'flex';
      if (this.formSignIn) this.formSignIn.style.display = 'none';

      if (this.toggleHintText) this.toggleHintText.textContent = 'Already have an account?';
      if (this.btnToggleMode) this.btnToggleMode.textContent = 'Sign In';
      this.inputSignUpName?.focus();
    }
  }

  private showAlert(message: string, type: 'error' | 'success'): void {
    if (!this.alertBox) return;
    if (!message) {
      this.alertBox.style.display = 'none';
      this.alertBox.textContent = '';
      return;
    }
    this.alertBox.className = `auth-view-alert ${type}`;
    this.alertBox.textContent = message;
    this.alertBox.style.display = 'block';
  }

  private clearAlert(): void {
    this.showAlert('', 'error');
  }

  private async handleSignIn(e: Event): Promise<void> {
    e.preventDefault();
    this.clearAlert();

    const email = this.inputSignInEmail?.value.trim() || '';
    const password = this.inputSignInPassword?.value || '';

    if (!email || !password) {
      this.showAlert('Please enter both your email address and password.', 'error');
      return;
    }

    if (this.btnSubmitSignIn) {
      this.btnSubmitSignIn.disabled = true;
      this.btnSubmitSignIn.textContent = 'Authenticating...';
    }

    const watchdog = setTimeout(() => {
      if (this.btnSubmitSignIn && this.btnSubmitSignIn.disabled) {
        this.btnSubmitSignIn.disabled = false;
        this.btnSubmitSignIn.textContent = 'Sign In & Enter Workspace →';
      }
    }, 4000);

    try {
      await AuthService.login(email, password);
      clearTimeout(watchdog);
      this.showAlert('Authentication successful! Entering workspace...', 'success');
      if (this.btnSubmitSignIn) {
        this.btnSubmitSignIn.disabled = false;
        this.btnSubmitSignIn.textContent = 'Sign In & Enter Workspace →';
      }
      setTimeout(() => {
        router.navigate('workspace');
      }, 150);
    } catch (err: any) {
      clearTimeout(watchdog);
      if (this.btnSubmitSignIn) {
        this.btnSubmitSignIn.disabled = false;
        this.btnSubmitSignIn.textContent = 'Sign In & Enter Workspace →';
      }
      this.showAlert(err.message || 'Invalid email or password. Please try again or create an account.', 'error');
    }
  }

  private async handleSignUp(e: Event): Promise<void> {
    e.preventDefault();
    this.clearAlert();

    const name = this.inputSignUpName?.value.trim() || '';
    const email = this.inputSignUpEmail?.value.trim() || '';
    const password = this.inputSignUpPassword?.value || '';

    if (!name || !email || !password) {
      this.showAlert('Please fill in your name, email, and password.', 'error');
      return;
    }

    if (password.length < 6) {
      this.showAlert('Password must be at least 6 characters long.', 'error');
      return;
    }

    if (this.btnSubmitSignUp) {
      this.btnSubmitSignUp.disabled = true;
      this.btnSubmitSignUp.textContent = 'Creating account...';
    }

    const watchdog = setTimeout(() => {
      if (this.btnSubmitSignUp && this.btnSubmitSignUp.disabled) {
        this.btnSubmitSignUp.disabled = false;
        this.btnSubmitSignUp.textContent = 'Create Account & Enter →';
      }
    }, 4000);

    try {
      await AuthService.signup(name, email, password);
      clearTimeout(watchdog);
      this.showAlert('Account created successfully! Entering workspace...', 'success');
      if (this.btnSubmitSignUp) {
        this.btnSubmitSignUp.disabled = false;
        this.btnSubmitSignUp.textContent = 'Create Account & Enter →';
      }
      setTimeout(() => {
        router.navigate('workspace');
      }, 150);
    } catch (err: any) {
      clearTimeout(watchdog);
      if (this.btnSubmitSignUp) {
        this.btnSubmitSignUp.disabled = false;
        this.btnSubmitSignUp.textContent = 'Create Account & Enter →';
      }
      this.showAlert(err.message || 'Registration failed. An account with this email may already exist.', 'error');
    }
  }
}

export const authViewController = new AuthViewController();
