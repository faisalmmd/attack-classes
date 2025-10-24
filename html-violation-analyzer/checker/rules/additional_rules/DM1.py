from html.parser import HTMLParser

name_informal = """ Input with same name """
description = """ Checks whether two or more inputs/select/textarea elements in a form have the same name """

class DM1(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "close"
        self._list_of_input_names = []
        self._list_of_radiobutton_names = []
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "form" and self._state == "close":
                self._state = "open"

        is_radio = False
        if tag in ["input", "select", "textarea"] and self._state == "open":
            # check if input is a radio button
            for name, value in attrs:
                if name == "type" and value == "radio":
                    is_radio = True

            # add name to list. if radio, skip if it is already known
            for name, value in attrs:
                if name == "name":
                    if is_radio:
                        # this is a new radio
                        if value not in self._list_of_radiobutton_names:
                            self._list_of_input_names.append(value)
                            self._list_of_radiobutton_names.append(value)
                    else:
                        self._list_of_input_names.append(value)

        
        amt_inputs = len(self._list_of_input_names)
        amt_unique_inputs = len(set(self._list_of_input_names))
        if  amt_inputs != amt_unique_inputs:
            if self._debug and self._state != "error":
                print(f"{tag} -> {attrs}")
            self._state = "error"

    def handle_endtag(self, tag):
        if tag == "form" and self._state == "open":
            self._list_of_input_names = []
            self._state = "close"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    dm1 = DM1(debug=debug)
    dm1.feed(html)
    res = dm1.is_valid()
    del dm1
    return res
