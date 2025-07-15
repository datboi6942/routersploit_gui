// RouterSploit GUI - Service Worker
// Provides offline functionality and caching for PWA

const CACHE_NAME = 'routersploit-gui-v1';
const urlsToCache = [
    '/',
    '/static/css/style.css',
    '/static/js/debug-app.js',
    '/static/js/sound-generator.js',
    '/static/manifest.json',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
    'https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js'
];

// Helper function to check if request can be cached
function canCacheRequest(request) {
    const url = new URL(request.url);
    
    // Don't cache chrome-extension requests
    if (url.protocol === 'chrome-extension:') {
        return false;
    }
    
    // Don't cache POST, PUT, DELETE requests
    if (request.method !== 'GET' && request.method !== 'HEAD') {
        return false;
    }
    
    // Don't cache requests with certain headers
    if (request.headers.get('cache-control') === 'no-cache' || 
        request.headers.get('cache-control') === 'no-store') {
        return false;
    }
    
    return true;
}

// Install Service Worker
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('Service Worker: Caching files');
                return cache.addAll(urlsToCache);
            })
            .then(() => {
                console.log('Service Worker: All files cached');
                return self.skipWaiting();
            })
    );
});

// Activate Service Worker
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Service Worker: Deleting old cache');
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => {
            console.log('Service Worker: Activated');
            return self.clients.claim();
        })
    );
});

// Fetch Event - Network First Strategy for API calls, Cache First for static assets
self.addEventListener('fetch', (event) => {
    // Skip non-cacheable requests early
    if (!canCacheRequest(event.request)) {
        return;
    }
    
    const requestUrl = new URL(event.request.url);
    
    // Handle API requests with Network First strategy
    if (requestUrl.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    // If we get a valid response and can cache, update the cache
                    if (response.status === 200 && canCacheRequest(event.request)) {
                        const responseClone = response.clone();
                        caches.open(CACHE_NAME)
                            .then((cache) => {
                                cache.put(event.request, responseClone);
                            })
                            .catch((error) => {
                                console.log('Service Worker: Cache put failed:', error);
                            });
                    }
                    return response;
                })
                .catch(() => {
                    // If network fails, try to serve from cache
                    return caches.match(event.request)
                        .then((cachedResponse) => {
                            if (cachedResponse) {
                                return cachedResponse;
                            }
                            // Return offline page for API requests
                            return new Response(
                                JSON.stringify({
                                    error: 'Network unavailable',
                                    message: 'This feature requires an internet connection'
                                }),
                                {
                                    headers: {
                                        'Content-Type': 'application/json'
                                    },
                                    status: 503
                                }
                            );
                        });
                })
        );
        return;
    }
    
    // Handle static assets with Cache First strategy
    event.respondWith(
        caches.match(event.request)
            .then((cachedResponse) => {
                // Return cached version if available
                if (cachedResponse) {
                    return cachedResponse;
                }
                
                // If not in cache, fetch from network
                return fetch(event.request)
                    .then((response) => {
                        // Don't cache if not a valid response or can't cache
                        if (!response || response.status !== 200 || response.type !== 'basic' || !canCacheRequest(event.request)) {
                            return response;
                        }
                        
                        // Clone the response
                        const responseToCache = response.clone();
                        
                        // Add to cache
                        caches.open(CACHE_NAME)
                            .then((cache) => {
                                cache.put(event.request, responseToCache);
                            })
                            .catch((error) => {
                                console.log('Service Worker: Cache put failed:', error);
                            });
                        
                        return response;
                    })
                    .catch(() => {
                        // If network fails and not in cache, return offline page
                        if (event.request.destination === 'document') {
                            return caches.match('/offline.html') || new Response(
                                '<html><body><h1>Offline</h1><p>This page is not available offline.</p></body></html>',
                                { headers: { 'Content-Type': 'text/html' } }
                            );
                        }
                        
                        // For other requests, return a generic offline response
                        return new Response('Offline', { status: 503 });
                    });
            })
    );
});

// Handle Background Sync
self.addEventListener('sync', (event) => {
    if (event.tag === 'background-sync') {
        event.waitUntil(
            // Perform background sync operations
            syncData()
        );
    }
});

// Handle Push Notifications
self.addEventListener('push', (event) => {
    if (event.data) {
        const data = event.data.json();
        
        const options = {
            body: data.body,
            icon: '/static/icons/icon-192x192.png',
            badge: '/static/icons/icon-72x72.png',
            vibrate: [100, 50, 100],
            data: {
                dateOfArrival: Date.now(),
                primaryKey: data.primaryKey
            },
            actions: [
                {
                    action: 'explore',
                    title: 'Open RouterSploit GUI',
                    icon: '/static/icons/icon-192x192.png'
                },
                {
                    action: 'close',
                    title: 'Close notification',
                    icon: '/static/icons/icon-192x192.png'
                }
            ]
        };
        
        event.waitUntil(
            self.registration.showNotification(data.title, options)
        );
    }
});

// Handle Notification Click
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    if (event.action === 'explore') {
        event.waitUntil(
            clients.openWindow('/')
        );
    } else if (event.action === 'close') {
        // Just close the notification
        return;
    } else {
        // Default action - open the app
        event.waitUntil(
            clients.openWindow('/')
        );
    }
});

// Background Sync Function
async function syncData() {
    try {
        // Sync any pending data when network is available
        const response = await fetch('/api/sync', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                timestamp: Date.now()
            })
        });
        
        if (response.ok) {
            console.log('Background sync completed successfully');
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}

// Message Handler
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
});

// Periodic Background Sync (if supported)
self.addEventListener('periodicsync', (event) => {
    if (event.tag === 'check-updates') {
        event.waitUntil(
            checkForUpdates()
        );
    }
});

// Check for Updates Function
async function checkForUpdates() {
    try {
        const response = await fetch('/api/version');
        const data = await response.json();
        
        if (data.version !== CACHE_NAME) {
            // New version available, notify user
            self.registration.showNotification('Update Available', {
                body: 'A new version of RouterSploit GUI is available',
                icon: '/static/icons/icon-192x192.png',
                actions: [
                    {
                        action: 'update',
                        title: 'Update Now'
                    }
                ]
            });
        }
    } catch (error) {
        console.error('Update check failed:', error);
    }
}

// Install prompt handling
self.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    
    // Store the event for later use
    self.installPromptEvent = event;
    
    // Show install banner
    self.registration.showNotification('Install RouterSploit GUI', {
        body: 'Install this app for better performance and offline access',
        icon: '/static/icons/icon-192x192.png',
        actions: [
            {
                action: 'install',
                title: 'Install'
            },
            {
                action: 'dismiss',
                title: 'Not Now'
            }
        ]
    });
});

// Console log for debugging
console.log('Service Worker: Registered'); 