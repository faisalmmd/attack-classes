// TC-OR-01: POSITIVE — location.href with user source
var next = new URLSearchParams(location.search).get('next');
location.href = next;

// TC-OR-02: POSITIVE — location.replace with document.referrer
window.location.replace(document.referrer);

// TC-OR-03: POSITIVE — location.assign with function call
location.assign(getRedirectUrl());

// TC-OR-04: NEGATIVE — static string literal
location.href = "/dashboard";

// TC-OR-05: NEGATIVE — hardcoded safe URL
location.href = "https://example.com/page";

// TC-OR-06: POSITIVE — window.open with variable
var target_url = getParam("url");
window.open(target_url);
