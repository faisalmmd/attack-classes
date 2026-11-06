// TC-PM-01: POSITIVE/CRITICAL — no origin check + data to innerHTML
window.addEventListener('message', function(event) {
    document.getElementById('widget').innerHTML = event.data;
});

// TC-PM-02: POSITIVE/HIGH — no origin check, no dangerous sink
window.addEventListener('message', function(event) {
    console.log("Received:", event.data);
    updateCounter(event.data.count);
});

// TC-PM-03: POSITIVE/MEDIUM — weak origin check with indexOf
window.addEventListener('message', function(e) {
    if (e.origin.indexOf('trusted.com') > -1) {
        processPayment(e.data);
    }
});

// TC-PM-04: POSITIVE/MEDIUM — wildcard target origin
var token = getSessionToken();
parent.postMessage(token, '*');

// TC-PM-05: NEGATIVE/INFO — strict origin check
window.addEventListener('message', function(e) {
    if (e.origin === 'https://trusted.example.com') {
        processData(e.data);
    }
});

// TC-PM-06: NEGATIVE — not a message listener at all
document.addEventListener('click', function(event) {
    handleClick(event.target);
});
