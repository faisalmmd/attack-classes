from html.parser import HTMLParser

name_informal = """ Elements with same id """
description = """ Checks whether two elements with the same id exist. """

class DC1(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._id_list = []
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k == "id":
                if v in self._id_list:
                    if self._debug:
                        print(v)
                    self._valid = False
                else:
                    self._id_list.append(v)

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    dc1 = DC1(debug=debug)
    dc1.feed(html)
    res = dc1.is_valid()
    del dc1
    return res
