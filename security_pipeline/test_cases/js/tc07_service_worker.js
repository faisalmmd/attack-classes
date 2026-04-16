// TC-SW-01: POSITIVE — broad scope registration
navigator.serviceWorker.register('/sw.js', { scope: '/' });

// TC-SW-02: POSITIVE — default scope
navigator.serviceWorker.register('/scripts/service-worker.js');

// TC-SW-03: POSITIVE — importScripts in SW
importScripts('https://cdn.example.com/analytics-sw.js');

// TC-SW-04: POSITIVE — fetch event listener
self.addEventListener('fetch', function(event) {
    event.respondWith(caches.match(event.request));
});

// TC-SW-05: NEGATIVE — commented out (known false positive with regex)
// navigator.serviceWorker.register('/old-sw.js', { scope: '/' });
