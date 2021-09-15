import idc
import idaapi
import idautils
# from contest import *

ref_types_data = {
0  : 'Data_Unknown',
1  : 'Data_Offset',
2  : 'Data_Write',
3  : 'Data_Read',
4  : 'Data_Text',
5  : 'Data_Informational',
}
ref_types_code = {
16 : 'Code_Far_Call',
17 : 'Code_Near_Call',
18 : 'Code_Far_Jump',
20 : 'Code_User',
}
ref_types_insidefunc = {
19 : 'Code_Near_Jump',
21 : 'Ordinary_Flow'
}

VIEWTITLE = "RefHunter"
SKYBLUE = 0xdfbc50

def printable_bytes(addr):
    output, length = '', 0
    asciimap = {x:chr(x) for x in range(0x20, 0x80)}
    asciimap.update({0xa:'<LF>', 0xd:'<CR>', 0x9:'<HT>'})
    
    while True:
        ch = ord(idc.get_bytes(addr, 1))
        if (ch >= 0x20 and ch <= 0x7f) or ch == 0xa or ch == 0xd or ch == 0x9:
            output += asciimap[ch]
            addr += 1
            length += 1
        else:
            break
    return output, length

def detail(addr, reftype):
    if reftype in ref_types_code:
	    return idc.get_func_name(addr)
    elif reftype in ref_types_data:
        a = hex(ord(idc.get_bytes(addr + 0, 1)))[2:].zfill(2)
        b = hex(ord(idc.get_bytes(addr + 1, 1)))[2:].zfill(2)
        c = hex(ord(idc.get_bytes(addr + 2, 1)))[2:].zfill(2)
        d = hex(ord(idc.get_bytes(addr + 3, 1)))[2:].zfill(2)
        return '0x%s (Unknown)' % (a+b+c+d)

class GetXrefs:
    def __init__(self, loc):
        self.xref_data = {} # all data (function, string, ..)
        self.xref_data_string = {} # only string amongst data
        self.xref_code = {}
        self.collect_allxrefs(loc)

    def collect_allxrefs(self, loc):
        addr_start  = get_func_attr(loc, FUNCATTR_START)
        addr_end    = get_func_attr(loc, FUNCATTR_END)
        for addr in range(addr_start, addr_end):
            for xref in idautils.XrefsFrom(addr):
                # data type
                if xref.type in ref_types_data: 
                    string, length = printable_bytes(xref.to)
                    
                    if len(string) >= 3:
                        create_strlit(addr, addr + length) # create_strlit(addr, addr + length, STRTYPE_C) in case of that's not asciified
                        self.xref_data_string[addr] = [xref.to, xref.type, '"%s"' % string]
                    
                    else:
                        self.xref_data[addr] = [xref.to, xref.type, detail(xref.to, xref.type)] # XrefTypeName(xref.type)
                # code type
                elif xref.type in ref_types_code:
                    self.xref_code[addr] = [xref.to, xref.type, detail(xref.to, xref.type)]
    
    def get_xref_data(self):
        return self.xref_data

    def get_xref_data_string(self):
        return self.xref_data_string

    def get_xref_code(self):
        return self.xref_code

class View(idaapi.simplecustviewer_t):
    def RefreshView(self, title):
        self.lineno = 0
        self.lines = {}
        self.Close()
        self.Create(title)
        self.Show()

    def line2addr(self, line): 
        address = ''
        for x in line.split():
            if x.startswith('0x'):
                address = x 
                break
        return int(address, 16)

    def draw_line(self, line):
        self.lines[self.lineno] = line
        self.lineno += 1
        self.AddLine(line)
    
    def get_line(self, lineno):
        return self.lines[lineno]
    
    def fix_line(self, lineno, line):
        self.lines[lineno] = line
        self.EditLine(lineno, line)

    def Create(self, title):
        cursor_addr = get_screen_ea()
        self.Getxref(cursor_addr)

        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.draw_line("   ___      _____ __          __         ")
        self.draw_line("  / _ \___ / _/ // /_ _____  / /____ ____")
        self.draw_line(" / , _/ -_) _/ _  / // / _ \/ __/ -_) __/")
        self.draw_line("/_/|_|\__/_//_//_/\_,_/_//_/\__/\__/_/  ")
        self.draw_line('')
        self.draw_line(idaapi.COLSTR(" Ctrl + <H>   Open", idaapi.SCOLOR_AUTOCMT))
        self.draw_line(idaapi.COLSTR(" ESC          Close", idaapi.SCOLOR_AUTOCMT))
        self.draw_line(idaapi.COLSTR(" <C>          [C]olor assembly line", idaapi.SCOLOR_AUTOCMT))
        self.draw_line(idaapi.COLSTR(" <R>          [R]efresh view", idaapi.SCOLOR_AUTOCMT))
        self.draw_line('-----------------------------------------')
        self.draw_line('')
        self.draw_line('     From    |     To     |    Detail')

        self.DrawLines(self.xref_code , " [CODE]")
        self.DrawLines(self.xref_data , " [DATA]")
        self.DrawLines(self.xref_data_string , " [STRING DATA]")
        
        return True
    
    def Getxref(self, cursor_addr):
        gx = GetXrefs(cursor_addr)
        self.xref_data           = gx.get_xref_data()
        self.xref_data_string    = gx.get_xref_data_string()
        self.xref_code           = gx.get_xref_code()
        
    def DrawLines(self, xrefdict, title): 
        self.draw_line('')
        self.draw_line(title)
        self.draw_line('')

        for addr in xrefdict:
            line  = ' '
            line += idaapi.COLSTR(' 0x{:<8x} '.format(addr), idaapi.SCOLOR_PREFIX)
            line += '|'
            line += idaapi.COLSTR(' 0x{:<8x} '.format(xrefdict[addr][0]), idaapi.SCOLOR_VOIDOP)
            line += '|'
            line += idaapi.COLSTR(' {}'.format(xrefdict[addr][2]), idaapi.SCOLOR_AUTOCMT)
            
            self.draw_line(line)

class Controller(View):
    
    def OnClick(self, shift):
        return True

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        word = self.GetCurrentWord()
        if not word: word = "<None>"
        
        try:
            # jump by address
            address = int(word, 16)
            ida_kernwin.jumpto(address)
        except ValueError:
            # jump by name
            address = get_name_ea_simple(word)
            ida_kernwin.jumpto(address)
        except:
            print( "Cannot jumpto %s" % word)

        return True

    def OnKeydown(self, vkey, shift):
        ### ESCAPE
        if vkey == 27:
            self.Close()

        ### Color line
        if vkey == ord('c') or vkey == ord('C'): 
            plainline = self.GetCurrentLine(notags=1)
            lineno = self.GetLineNo()

            # filter invalid line 
            if not plainline: return False
            if plainline.count('|') <2: return False 
            
            colorline = self.get_line(lineno)
            if plainline.startswith('*'):
                # set color
                address = self.line2addr(plainline)
                ORIGCOLOR = get_color(address, CIC_FUNC)
                set_color(address, CIC_ITEM, ORIGCOLOR)
                # set line
                colorline = colorline.replace('*', ' ', 1)
                self.fix_line(lineno, colorline)
            else:
                # set color
                address = self.line2addr(plainline)
                set_color(address, CIC_ITEM, SKYBLUE)
                # set line
                colorline = '*' + colorline.replace(' ', '', 1) # subtract ' ' and add '*' at start
                self.fix_line(lineno, colorline)
            self.RefreshCurrent()

        ### Refresh view
        elif vkey == ord('r') or vkey == ord('R'):
            print ("refreshing....")
            self.RefreshView(VIEWTITLE)

def hoykeyfunc():
    v = Controller()
    v.RefreshView(VIEWTITLE)
    

if __name__=='__main__':
    ida_expr.compile_idc_text('static py_hoykeyfunc() { RunPythonStatement("hoykeyfunc()"); }')
    ida_kernwin.add_idc_hotkey("Ctrl+H", 'py_hoykeyfunc')
