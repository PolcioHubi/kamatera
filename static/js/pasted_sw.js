(() => {
    if (!('serviceWorker' in navigator)) return;
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js?v=20250808')
            .then(reg => {
                try { console.log('ServiceWorker registration successful with scope:', reg.scope); } catch (_) {}
            })
            .catch(err => {
                try { console.log('ServiceWorker registration failed:', err); } catch (_) {}
            });
    });
})();