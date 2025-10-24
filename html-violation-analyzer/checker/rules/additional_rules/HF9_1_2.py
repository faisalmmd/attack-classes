from html.parser import HTMLParser

name_informal = """ SVG """
description = """ Checks <svg> for any disallowed element. """

class HF9_1(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._debug = debug
        self._state = "html"
        self._title_type = "html"
        self._desc_type = "html"
        self._foreignobject_type = "html"
        self._text_integration_points = ["mi", "mo", "mn", "ms", "mtext"]
        self._html_integration_points = ["foreignobject", "desc", "title"]

        self._svg_not_allowed_tags = ["b", "big", "blockquote", "body", "br", "center", "code", "dd", "div",
                "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li",
                "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong",
                "strike", "sub", "sup", "table", "tt", "u", "ul", "var", "br", "font"]

    def handle_starttag(self, tag, attrs):
        # print(f"{tag} open in {self._state}")
        if self._state == "html":
            if tag == "math":
                self._state = "math"
            if tag == "svg":
                self._state = "svg"
            if tag == "title":
                self._title_type = "html"
            return

        if self._state == "math":
            if tag in self._text_integration_points:
                self._state = "html"
            if tag in "annotation-xml" and "encoding" in attrs:
                if attrs["encoding"] in ["text/html", "application/xhtml+xml"]:
                    self._state = "html"           
            return

        if self._state == "svg":
            if tag in self._html_integration_points:
                self._state = "html"
            if tag in self._svg_not_allowed_tags:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                self._state = "error"
            if tag == "title":
                self._title_type = "svg"
            return            

    def handle_endtag(self, tag):
        # print(f"{tag} close in {self._state}")
        if self._state == "html":
            # title has extra case, as it exists in html and svg
            if tag == "foreignobject" and self._foreignobject_type == "html": 
                self._state = "html"
            elif tag == "foreignobject" and self._foreignobject_type == "svg":
                self._state = "svg"
            
            if tag == "desc" and self._desc_type == "html": 
                self._state = "html"
            elif tag == "desc" and self._desc_type == "svg":
                self._state = "svg"
            
            if tag == "title" and self._title_type == "html": 
                self._state = "html"
            elif tag == "title" and self._title_type == "svg":
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
    hf9_1 = HF9_1(debug=debug)
    hf9_1.feed(html)
    res = hf9_1.is_valid()
    del hf9_1
    return res
