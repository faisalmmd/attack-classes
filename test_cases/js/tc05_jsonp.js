// TC-JP-01: POSITIVE — callback parameter in URL
var url = "/api/users?callback=handleUsers";
loadScript(url);

// TC-JP-02: POSITIVE — jQuery JSONP config
$.ajax({
    url: "/api/data",
    dataType: "jsonp",
    success: function(data) { render(data); }
});

// TC-JP-03: POSITIVE — jQuery jsonpCallback setting
$.ajax({
    url: "/api/feed",
    jsonpCallback: "myHandler",
    dataType: "jsonp"
});

// TC-JP-04: POSITIVE — Script tag with JSONP endpoint (in a string, simulating HTML)
var tag = '<script src="https://api.example.com/data?callback=processData"></script>';

// TC-JP-05: NEGATIVE — regular JSON, no callback
fetch("/api/users?format=json");

// TC-JP-06: POSITIVE — JSONP variant parameter name
var endpoint = "/api/search?jsonpcallback=handle&q=test";
