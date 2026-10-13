import { draggableMagnifier } from './ui/magnifier.js';
import { meticLens } from './ui/lens.js';
import { liveDemo } from './ui/liveDemo.js';
import { progressiveBuild } from './ui/progressiveBuild.js';
import { router } from './ui/router.js';
import { initApp } from './ui/app.js';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize client-side view router
  router.init();

  // 2. Initialize Draggable Physical Magnifier & Malware X-Ray
  draggableMagnifier.init();

  // 3. Initialize signature technical inspection lens (keyboard [I] & fallback)
  meticLens.init();

  // 3. Initialize progressive page construction section
  progressiveBuild.init();

  // 4. Initialize live product demonstration with authentic SBI KYC scam analysis
  liveDemo.init();

  // 5. Initialize Authentication interactions
  const authForm = document.getElementById('authForm') as HTMLFormElement | null;
  const btnAuthDemo = document.getElementById('btnAuthDemo') as HTMLButtonElement | null;

  authForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    router.navigate('workspace');
  });

  btnAuthDemo?.addEventListener('click', () => {
    router.navigate('workspace');
  });

  // 6. Initialize existing full-featured Scam Spotter scanner workspace
  initApp();
});
