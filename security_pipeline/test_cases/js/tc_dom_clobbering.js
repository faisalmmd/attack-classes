// DOM Clobbering JS_RELIANCE Test Cases
// Reference: Liu et al. USENIX Security 2025, Lekies et al. USENIX Security 2021,
//            Khodayari & Pellegrino IEEE S&P 2023

// TC-DC-J-01: POSITIVE HIGH — dynamic window[variable] access
// If the variable is predictable, a named element can clobber the target.
var key = location.hash.slice(1);
var plugin = window[key];
plugin.init();

// TC-DC-J-02: POSITIVE HIGH — document.scripts collection access
// Liu et al. 2025 motivating example: shadowed by <iframe name="scripts">
var e = document.scripts || document.getElementsByTagName("script") || [];
for (var h = 0; h < e.length; ++h) {
  if (e[h].src.indexOf("apis.google.com") >= 0) {
    // process script
  }
}

// TC-DC-J-03: POSITIVE HIGH — security global in conditional without init
// DOM elements are truthy: if attacker injects <form name="isAdmin">,
// this check always passes.
if (isAdmin) {
  renderAdminPanel();
}

// TC-DC-J-04: POSITIVE MEDIUM — window.config direct access
// <form name="config"> makes window.config an HTMLFormElement.
// window.config.csrfToken returns undefined silently.
var token = window.config && window.config.csrfToken;
fetch('/api/data', { headers: { 'X-CSRF': token } });

// TC-DC-J-05: POSITIVE MEDIUM — document.auth named property access
// Named form/anchor elements accessible directly as document.elementName.
var authState = document.auth;
if (authState && authState.isValid) {
  grantAccess();
}

// TC-DC-J-06: POSITIVE HIGH — CSP nonce read from global
// Khodayari & Pellegrino S&P 2023 §4: DOM clobbering can forge the nonce
// value used by dynamically-loaded scripts, bypassing CSP.
var scriptNonce = window.nonce || document.querySelector('script').nonce;
var s = document.createElement('script');
s.nonce = scriptNonce;
s.src = '/bundle.js';
document.head.appendChild(s);

// TC-DC-J-07: POSITIVE LOW — bare security variable in conditional
// If isLoggedIn is undefined and <form name="isLoggedIn"> exists,
// browser may supply a DOM element (truthy) instead of false.
if (isLoggedIn && userRole === 'admin') {
  showDashboard();
}

// TC-DC-J-08: NEGATIVE — document.getElementById (defensive; explicit DOM API)
// Does not rely on namespace promotion; immune to DOM clobbering.
var configEl = document.getElementById('config-data');
var csrfToken = configEl ? configEl.dataset.token : null;

// TC-DC-J-09: NEGATIVE — window.location.href (not a named property access pattern)
// This is normal navigation, not a clobbering-susceptible pattern.
window.location.href = '/dashboard';

// TC-DC-J-10: NEGATIVE — window.addEventListener (not a clobberable pattern)
window.addEventListener('load', function() { console.log('ready'); });
