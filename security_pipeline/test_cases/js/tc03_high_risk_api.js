// TC-API-01: POSITIVE — Geolocation
navigator.geolocation.getCurrentPosition(function(pos) { console.log(pos); });

// TC-API-02: POSITIVE — Camera access
navigator.mediaDevices.getUserMedia({video: true, audio: false});

// TC-API-03: POSITIVE — WebRTC IP leak
var pc = new RTCPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});

// TC-API-04: POSITIVE — Clipboard read
navigator.clipboard.readText().then(text => sendToServer(text));

// TC-API-05: POSITIVE — Battery status
navigator.getBattery().then(function(battery) { console.log(battery.level); });

// TC-API-06: NEGATIVE — string mention (known false positive)
console.log("navigator.geolocation is a browser API");

// TC-API-07: POSITIVE — Web Bluetooth
navigator.bluetooth.requestDevice({filters: [{services: ['battery_service']}]});
