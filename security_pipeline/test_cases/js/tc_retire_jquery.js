/*!
 * jQuery JavaScript Library v1.9.1
 * http://jquery.com/
 * Copyright 2013 jQuery Foundation and other contributors
 * Released under the MIT license
 */
jQuery.fn.jquery = "1.9.1";
(function(window, undefined) {
    // Simulated jQuery 1.9.1 content for testing
    var jQuery = function(selector) { return new jQuery.fn.init(selector); };
    jQuery.fn = jQuery.prototype = { jquery: "1.9.1", constructor: jQuery };
    window.jQuery = window.$ = jQuery;
})(window);
