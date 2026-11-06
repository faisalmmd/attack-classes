// TC-PP-01: POSITIVE — Direct Object.prototype assignment
Object.prototype.isAdmin = true;

// TC-PP-02: POSITIVE — jQuery deep extend
$.extend(true, {}, userData);

// TC-PP-03: POSITIVE — Lodash _.merge
_.merge(config, req.body);

// TC-PP-04: POSITIVE — Lodash _.defaultsDeep
_.defaultsDeep(options, userOpts);

// TC-PP-05: POSITIVE — __proto__ access
obj.__proto__.polluted = 1;

// TC-PP-06: NEGATIVE — shallow extend (no true first arg)
$.extend({}, defaults);

// TC-PP-07: NEGATIVE — Object.assign (does not recurse)
Object.assign({}, source);

// TC-PP-08: NEGATIVE — defense, not attack
Object.freeze(Object.prototype);
