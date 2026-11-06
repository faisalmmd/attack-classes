// TC-RD-01: POSITIVE — nested quantifier
var emailRegex = /^([a-zA-Z0-9]+)+@example\.com$/;

// TC-RD-02: POSITIVE — quantified alternation
var bad = /^(a|a)+$/;

// TC-RD-03: POSITIVE — nested quantifier via constructor
var pattern = new RegExp("^(\\d+\\.)+$");

// TC-RD-04: NEGATIVE — single quantifier, safe
var ok1 = /^[a-zA-Z0-9]+$/;

// TC-RD-05: NEGATIVE — bounded quantifiers, safe
var ok2 = /^\d{3}-\d{4}$/;
