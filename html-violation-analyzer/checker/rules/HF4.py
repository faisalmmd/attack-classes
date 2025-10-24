from html.parser import HTMLParser

name_informal = """ Table """
description = """ Checks if table only contians allowed stuff. """

class HF5(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._stack = []
        self._debug = debug

    def handle_starttag(self, tag, attrs):

        if self._state == "error":
            return

        # init
        if self._state == "init" and tag == "table":
            self._state = "in_table"
            self._stack.append(tag)

        # in table
        elif self._state == "in_table" and tag == "caption":
            # We ignore broken tables inside a caption as this is not the goal of the rule
            self._state = "in_caption"
        elif self._state == "in_table" and tag in ["colgroup", "col"]:
            self._state = "in_colgroup"
        elif self._state == "in_table" and tag == "col":
            pass # open colgroup and close it
        elif self._state == "in_table" and tag in ["tbody", "tfoot", "thead"]:
            self._state = "in_table_body"
            self._stack.append(tag)
        elif self._state == "in_table" and tag in ["tr"]:
            self._state = "in_row"
            self._stack.append(tag)
        elif self._state == "in_table" and tag in ["td", "th"]:
            self._state = "in_cell"
            self._stack.append(tag)
        elif self._state == "in_table" and tag == "template":
            # We ignore broken tables inside a caption
            self._state = "in_template"
        elif self._state == "in_table" and tag == "script":
            self._state = "in_script"
        elif self._state == "in_table" and tag == "style":
            self._state = "in_style"
        elif self._state == "in_table" and tag == "form":
            self._state = "in_form"
        elif self._state == "in_table" and tag == "input" and "type" in attrs and attrs["type"] == "hidden":
            self._state = "in_input"
        elif self._state == "in_table":
            if self._debug:
                print(f"Error 7:{tag} -> {attrs}")
            self._state = "error"

        # in colgroup.
        elif self._state == "in_colgroup" and tag == "col":
            pass
        elif self._state == "in_colgroup" and tag == "template":
            self._state = "in_colgroup_template"
        elif self._state == "in_colgroup" and tag == "style":
            self._state = "in_colgroup_style"
        elif self._state == "in_colgroup":
            if self._debug:
                print(f"Error 6:{tag} -> {attrs}")
            self._state = "error"


        # in table body. Also, ignore miss-nested other table elements
        elif self._state == "in_table_body" and tag == "tr":
            self._state = "in_row"
            self._stack.append(tag)
        elif self._state == "in_table_body" and tag in ["th", "td"]:
            self._state = "in_cell"
            self._stack.append(tag)
        elif self._state == "in_table_body" and tag == "script":
            self._state = "in_script_in_table_body"
        elif self._state == "in_table_body" and tag == "style":
            self._state = "in_style_in_table_body"
        elif self._state == "in_table_body" and tag == "template":
            self._state = "in_template_in_table_body"
        elif self._state == "in_table_body":
            if self._debug:
                print(f"Error 5:{tag} -> {attrs}")
            self._state = "error"

        # in row
        elif self._state == "in_row" and tag in ["th", "td"]:
            self._state = "in_cell"
            self._stack.append(tag)
        elif self._state == "in_row" and tag == "script":
            self._state = "in_script_in_row"
        elif self._state == "in_row" and tag == "style":
            self._state = "in_style_in_row"
        elif self._state == "in_row":
            if self._debug:
                print(f"Error 4:{tag} -> {attrs}")
            self._state = "error"

        # in cell. If a nested table, begin a new table
        # Everything else is fine here
        elif self._state == "in_cell" and tag == "table":
            self._state = "in_table"
            self._stack.append(tag)
        elif self._state == "in_cell":
            pass

        # print(f"STag: {tag}\t-> {self._state}\n\t{self._stack}")

    def handle_closing_table(self):

        if len(self._stack) == 0 or "table" not in self._stack:
            if self._debug:
                print(f"Error stack: table")
            self._state = "error"
            return


        while self._stack.pop() != "table":
            continue

        if len(self._stack) == 0:
            self._state = "init"
        else:
            # Can only be in cell
            self._state = "in_cell"

    def handle_endtag(self, tag):

        if self._state == "error":
            return
          
        # Closing table always closes tables
        if tag  == "table" and self._state != "init":
            self.handle_closing_table()

        # close table (if it is not a closing table or template, it's an error)       
        elif self._state == "in_table" and tag == "template":
            self.handle_closing_table()
        elif self._state == "in_table":
            if self._debug:
                print(f"Error 6: Closing {tag}")
            self._state = "error"

        # I don't care what the content is
        elif self._state == "in_caption" and tag == "caption":
            self._state = "in_table"
        elif self._state == "in_template" and tag == "template":
            self._state = "in_table"
        elif self._state == "in_colgroup_template" and tag == "template":
            self._state = "in_colgroup"
        elif self._state == "in_script" and tag == "script":
            self._state = "in_table"
        elif self._state == "in_script_in_table_body" and tag == "script":
            self._state = "in_table_body"
        elif self._state == "in_script_in_row" and tag == "script":
            self._state = "in_row"
        elif self._state == "in_style_in_row" and tag == "style":
            self._state = "in_row"
        elif self._state == "in_style" and tag == "style":
            self._state = "in_table"
        elif self._state == "in_colgroup_style" and tag == "style":
            self._state = "in_colgroup"
        elif self._state == "in_style_in_table_body" and tag == "style":
            self._state = "in_table_body"
        elif self._state == "in_template_in_table_body" and tag == "template":
            self._state = "in_table_body"
        elif self._state == "in_form" and tag == "form":
            self._state = "in_table"
        elif self._state == "in_input" and tag == "input":
            self._state = "in_table"
        elif self._state == "in_colgroup" and tag == "colgroup": # there is no closing col
            self._state = "in_table"

        # in table body
        elif self._state == "in_table_body" and tag in ["tbody", "tfoot", "thead"]:
            if len(self._stack) < 1:
                if self._debug:
                    print(f"Error stack: in table body")
                self._state = "error"
                return
            self._stack.pop()
            self._state = "in_table"

        # in row
        elif self._state == "in_row" and tag in ["tr"]:
            if len(self._stack) < 1:
                if self._debug:
                    print(f"Error stack: in row")
                self._state = "error"
                return
            self._stack.pop()
            prv_ele = self._stack[-1]
            if prv_ele in ["tbody", "tfoot", "thead"]:
                self._state = "in_table_body"
            elif prv_ele == "table":
                self._state = "in_table"

        # in cell
        elif self._state == "in_cell" and tag in ["th", "td"]:
            if len(self._stack) < 1:
                if self._debug:
                    print(f"Error stack: in cell")
                self._state = "error"
                return
            self._stack.pop()
            prv_ele = self._stack[-1]
            if prv_ele == "tr":
                self._state = "in_row"
            elif prv_ele in ["tbody", "tfoot", "thead"]:
                self._state = "in_table_body"
            elif prv_ele == "table":
                self._state = "in_table"

        # print(f"ETag: {tag}\t-> {self._state}\n\t{self._stack}")


    def handle_data(self, data):

        if self._state == "error":
            return

        # if data.strip() != '':
        #    print(f"Enter data {data} in {self._state}")
        if data.strip() == '':
            pass
        elif self._state in ["in_table", "in_colgroup", "in_table_body", "in_row"]:
            if self._debug:
                print(f"Error 1 {self._state}: {data}")
            self._state = "error"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    hf5 = HF5(debug=debug)
    hf5.feed(html)
    res = hf5.is_valid()
    del hf5
    return res
