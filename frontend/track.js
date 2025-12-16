// Flowlytics Tracking Script
// Add this to any website to track page views

(function() {
    'use strict';
    
    // Configuration
    const TRACKER_URL = 'http://localhost:8080/track';
    
    // Get current page information
    function getPageInfo() {
        return {
            domain: window.location.hostname,
            path: window.location.pathname + window.location.search,
            referrer: document.referrer || '',
            timestamp: new Date().toISOString()
        };
    }
    
    // Send tracking event
    function track(eventData) {
        const params = new URLSearchParams({
            domain: eventData.domain,
            path: eventData.path,
            referrer: eventData.referrer
        });
        
        // Use beacon API for reliable tracking
        if (navigator.sendBeacon) {
            navigator.sendBeacon(`${TRACKER_URL}?${params.toString()}`);
        } else {
            // Fallback for older browsers
            const img = new Image();
            img.src = `${TRACKER_URL}?${params.toString()}`;
        }
    }
    
    // Track page view on load
    function trackPageView() {
        const pageInfo = getPageInfo();
        track(pageInfo);
    }
    
    // Auto-track page view
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', trackPageView);
    } else {
        trackPageView();
    }
    
    // Track SPA navigation (for single page applications)
    let currentPath = window.location.pathname;
    const observer = new MutationObserver(() => {
        if (window.location.pathname !== currentPath) {
            currentPath = window.location.pathname;
            trackPageView();
        }
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Expose tracking function globally
    window.flowlytics = {
        track: track,
        trackPageView: trackPageView
    };
    
})();