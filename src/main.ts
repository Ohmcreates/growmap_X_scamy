import { draggableMagnifier } from './ui/magnifier.js';
import { liveDemo } from './ui/liveDemo.js';
import { progressiveBuild } from './ui/progressiveBuild.js';
import { router } from './ui/router.js';
import { initApp } from './ui/app.js';

import { authViewController } from './ui/authView.js';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initialize client-side view router
  router.init();

  // 2. Initialize Draggable Physical Magnifier & Malware X-Ray
  draggableMagnifier.init();

  // 3. Initialize progressive page construction section
  progressiveBuild.init();

  // 4. Initialize live product demonstration with authentic SBI KYC scam analysis
  liveDemo.init();

  // 5. Initialize Authentication interactions (Sign In & Sign Up)
  authViewController.init();

  // 6. Initialize existing full-featured Scam Spotter scanner workspace
  initApp();
});
