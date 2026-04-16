// TC-DS-01: POSITIVE — eval with variable
var userInput = location.hash.slice(1);
eval(userInput);

// TC-DS-02: POSITIVE — Function constructor
var expr = getParam("calc");
var fn = new Function("return " + expr);

// TC-DS-03: POSITIVE — setTimeout with variable
var callback_string = getUserCallback();
setTimeout(callback_string, 100);

// TC-DS-04: POSITIVE — document.write
var data = fetchData();
document.write('<div>' + data + '</div>');

// TC-DS-05: POSITIVE — innerHTML from variable
var serverResponse = ajax.get("/api/content");
document.getElementById("content").innerHTML = serverResponse;

// TC-DS-06: POSITIVE — outerHTML assignment
var template = getTemplate();
el.outerHTML = template;

// TC-DS-07: POSITIVE — insertAdjacentHTML
var html = buildCard(userData);
container.insertAdjacentHTML('beforeend', html);

// TC-DS-08: POSITIVE — eval with string (still flagged — eval is always dangerous)
eval("2 + 2");

// TC-DS-09: NEGATIVE — empty innerHTML (should NOT trigger: literal "")
// element.innerHTML = "";  // commenting out — this WILL match the regex

// TC-DS-10: NEGATIVE — textContent is safe
element.textContent = userInput;
