// Scam Spotter — Content Script Link Interceptor

function scanPageLinks() {
  const links = document.querySelectorAll('a[href]');
  links.forEach((link) => {
    const href = link.getAttribute('href') || '';
    if (href.startsWith('http')) {
      chrome.runtime.sendMessage({ action: 'CHECK_URL', url: href }, (response) => {
        if (response && response.isSuspicious) {
          link.style.border = '2px dashed #ef4444';
          link.title = `⚠️ Scam Spotter Warning: ${response.reason}`;
        }
      });
    }
  });
}

// Run scan once page has loaded
if (document.readyState === 'complete') {
  scanPageLinks();
} else {
  window.addEventListener('load', scanPageLinks);
}
