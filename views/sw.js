// Minimal service worker — registered only so the browser considers /driver
// installable as a standalone app. This is a live real-time tracking tool,
// so there's no offline mode to provide; the fetch handler intentionally
// does nothing and lets every request pass through to the network normally.
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', () => {});
