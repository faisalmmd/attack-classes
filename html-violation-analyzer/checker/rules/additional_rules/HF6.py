from html.parser import HTMLParser

name_informal = """ Form Tag Nesting """
description = """ Checks if all tags inside a from are closed. Thus, no element is nested which could lead to nested forms. """

# TODO ignore option
# TODO ignore content of table, but put table tag on stack
class HF6(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._void_elements = ["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]
        self._stack_of_open_elements = []
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "form" and self._state != "error":
            self._state = "in_form"
            self._stack_of_open_elements.append(tag)
        elif self._state == "in_form" and tag not in self._void_elements:
            self._stack_of_open_elements.append(tag)

    def handle_endtag(self, tag):
        if self._state == "in_form":
            if tag in self._stack_of_open_elements:
                self._stack_of_open_elements.remove(tag)

        if tag == "form" and len(self._stack_of_open_elements) != 0:
            if (self._debug):
                print(f"Found left opened tags: {self._stack_of_open_elements}")
            self._state = "error"

        if len(self._stack_of_open_elements) == 0:
            self._state = "init"        

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    hf6 = HF6(debug=debug)
    hf6.feed(html)
    res = hf6.is_valid()
    del hf6
    return res