from html.parser import HTMLParser

name_informal = """ Math (HTML Specs) """
description = """ Checks <math> for any disallowed element. (HTML Specs)"""

class HF9_4(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._debug = debug
        self._state = "html"
        self._text_integration_points = ["mi", "mo", "mn", "ms", "mtext"]
        self._html_integration_points = ["foreignobject", "desc", "title"]
        
        self._not_math_tags = ["b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em", "embed",
        "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p", "pre",
        "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var", "p", "br"]

    def handle_starttag(self, tag, attrs):
        if self._state == "html":
            if tag == "math":
                self._state = "math"
            if tag == "svg":
                self._state = "svg"
            return

        if self._state == "math":
            if tag in self._text_integration_points:
                self._state = "html"
            if tag in "annotation-xml" and "encoding" in attrs:
                if attrs["encoding"] in ["text/html", "application/xhtml+xml"]:
                    self._state = "html"    
            if tag not in self._not_math_tags:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                self._state = "error"    
            if tag == "font":
                for k, _ in attrs:
                    if k in ["color", "face", "size"]:
                        if self._debug:
                            print(f"{tag} -> {attrs}")
                        self._state = "error"   
            return

        if self._state == "svg":
            if tag in self._html_integration_points:
                self._state = "html"
            return            

    def handle_endtag(self, tag):
        if self._state == "html":
            if tag in self._html_integration_points:
                self._state = "svg"
            if tag in self._text_integration_points:
                self._state = "math"
            if tag == "annotation-xml":
                self._state = "math"
            return

        if self._state == "math" and tag == "math":
            self._state = "html"
            return

        if self._state == "svg" and tag == "svg":
            self._state = "html"
            return

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    hf9_4 = HF9_4(debug=debug)
    hf9_4.feed(html)
    res = hf9_4.is_valid()
    del hf9_4
    return res
