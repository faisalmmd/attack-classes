from html.parser import HTMLParser

name_informal = """ Modify body attributes """
description = """ Checks for the existing of active formatting. """

class HF4(HTMLParser):

    # Active formatting happens when an element is closed that was not opened in the active formatting element.
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._stacks_of_formatting_elements = []
        self._active_formatting_elements = ["a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u"]
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        for _, stack in self._stacks_of_formatting_elements:
            stack.append(tag)
        if tag in self._active_formatting_elements:
            ele = (tag, [tag])
            self._stacks_of_formatting_elements.append(ele)

        if self._debug:
            for ele, stack in self._stacks_of_formatting_elements:
                # print(f"Start {ele} -> {stack}")
                pass

    def handle_endtag(self, tag):
        stacks_to_remove = []
        for idx, ele_stack in enumerate(self._stacks_of_formatting_elements):
            if tag not in ele_stack[1]:
                if self._debug:
                    print(f"{tag} closes that is not in formatting element {ele_stack[0]}")
                self._valid = False
                break
            # remove only one element as element could be two time in stack
            ele_stack[1].remove(tag)

            # check if origin tag was closed. element is not on the stack if closed
            # Ignore exisitng open tags
            if (ele_stack[0] == tag and tag not in ele_stack[1]) \
                or len(ele_stack[1]) == 0:
                stacks_to_remove.append(ele_stack)

        for ele_stack in stacks_to_remove:
            self._stacks_of_formatting_elements.remove(ele_stack)
            
        if self._debug:
            for ele, stack in self._stacks_of_formatting_elements:
                # print(f"End of {tag}: {ele} -> {stack}")
                pass

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    hf4 = HF4(debug=debug)
    hf4.feed(html)
    res = hf4.is_valid()
    del hf4
    return res
