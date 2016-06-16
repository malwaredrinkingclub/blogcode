# Blog 1 code
# Use vivisect-based code to generate wildcarded Yara rules for code
# (relying on some IDA features also currently)

import struct
import vivisect
from envi.archs.i386 import *
import envi.archs.i386.opcode86 as opcode86

try:
    import idc
    import idaapi
except ImportError:
    print "Couldn't import IDA modules; some functionality may not work as expected"

DEBUG = False

class i386DisasmParts(i386Disasm):
    """Diassembler customisation to track the bytes we want to keep"""
    # This method is copied from the original, with minor changes to track the
    # instruction parts we want to identify in an extra field of the opcode
    # object returned
    def disasm(self, bytez, offset, va):

        # CHANGE
        # MODRM and SIB are part of operand data
        partz = {"prefix": "", "opcode": "", "operands": []}

        # Stuff for opcode parsing
        tabdesc = all_tables[0] # A tuple (optable, shiftbits, mask byte, sub, max)
        startoff = offset # Use startoff as a size knob if needed

        # Stuff we'll be putting in the opcode object
        optype = None # This gets set if we successfully decode below
        mnem = None 
        operands = []

        prefixes = 0

        while True:

            obyte = ord(bytez[offset])

            # This line changes in 64 bit mode
            p = self._dis_prefixes[obyte]
            if p == None:
                break
            if obyte == 0x66 and ord(bytez[offset+1]) == 0x0f:
                break
            prefixes |= p
            # CHANGE
            partz["prefix"] += bytez[offset]
            offset += 1
            continue

        #pdone = False
        while True:

            obyte = ord(bytez[offset])
            # CHANGE
            partz["opcode"] += bytez[offset]

            if (obyte > tabdesc[4]):
                #print "Jumping To Overflow Table:", tabdesc[5]
                tabdesc = all_tables[tabdesc[5]]

            tabidx = ((obyte - tabdesc[3]) >> tabdesc[1]) & tabdesc[2]
            #print "TABIDX: %d" % tabidx
            opdesc = tabdesc[0][tabidx]
            #print 'OPDESC: %s' % repr(opdesc)

            # Hunt down multi-byte opcodes
            nexttable = opdesc[0]
            #print "NEXT",nexttable,hex(obyte)
            if nexttable != 0: # If we have a sub-table specified, use it.
                #print "Multi-Byte Next Hop For",hex(obyte),opdesc[0]
                tabdesc = all_tables[nexttable]

                # In the case of 66 0f, the next table is *already* assuming we ate
                # the 66 *and* the 0f...  oblidge them.
                if obyte == 0x66 and ord(bytez[offset+1]) == 0x0f:
                    offset += 1
                    # CHANGE
                    partz["opcode"] += bytez[offset]

                # Account for the table jump we made
                offset += 1
                continue

            # We are now on the final table...
            #print repr(opdesc)
            mnem = opdesc[6]
            optype = opdesc[1]
            if tabdesc[2] == 0xff:
                offset += 1 # For our final opcode byte
            break

        if optype == 0:
            #print tabidx
            #print opdesc
            #print "OPTTYPE 0"
            raise envi.InvalidInstruction(bytez=bytez[startoff:startoff+16], va=va)

        operoffset = 0
        # Begin parsing operands based off address method
        for i in operand_range: # (2, 3, 4)

            oper = None # Set this if we end up with an operand
            osize = 0

            # Pull out the operand description from the table
            operflags = opdesc[i]
            opertype = operflags & opcode86.OPTYPE_MASK
            addrmeth = operflags & opcode86.ADDRMETH_MASK

            # If there are no more operands, break out of the loop!
            if operflags == 0:
                break

            #print "ADDRTYPE: %.8x OPERTYPE: %.8x" % (addrmeth, opertype)
            tsize = self._dis_calc_tsize(opertype, prefixes, operflags)
            #print hex(opertype),hex(addrmeth), hex(tsize)

            # If addrmeth is zero, we have operands embedded in the opcode
            if addrmeth == 0:
                osize = 0
                oper = self.ameth_0(operflags, opdesc[5+i], tsize, prefixes)

            else:
                #print "ADDRTYPE",hex(addrmeth)
                ameth = self._dis_amethods[addrmeth >> 16]
                #print "AMETH",ameth
                if ameth == None:
                    raise Exception("Implement Addressing Method 0x%.8x" % addrmeth)

                # NOTE: Depending on your addrmethod you may get beginning of operands, or offset
                try:
                    if addrmeth == opcode86.ADDRMETH_I or addrmeth == opcode86.ADDRMETH_J:
                        osize, oper = ameth(bytez, offset+operoffset, tsize, prefixes, operflags)

                        # If we are a sign extended immediate and not the same as the other operand,
                        # do the sign extension during disassembly so nothing else has to worry about it..
                        if operflags & opcode86.OP_SIGNED and len(operands) and tsize != operands[-1].tsize:
                            otsize = operands[-1].tsize
                            oper.imm = e_bits.sign_extend(oper.imm, oper.tsize, otsize)
                            oper.tsize = otsize

                    else:
                        osize, oper = ameth(bytez, offset, tsize, prefixes, operflags)

                except struct.error, e:
                    # Catch struct unpack errors due to insufficient data length
                    raise envi.InvalidInstruction(bytez=bytez[startoff:startoff+16])

            if oper != None:
                # This is a filty hack for now...
                oper._dis_regctx = self._dis_regctx
                operands.append(oper)
                tweak = 0
                # Sometimes the modrm or sib bytes get passed both as part of the opcode *and* as part of the first operand
                # So skip this byte(s) if we need to
                if (len(partz["prefix"]) + len(partz["opcode"])) > (offset+operoffset):
                    tweak = (len(partz["prefix"]) + len(partz["opcode"])) - (offset+operoffset)
 
                if osize > 0:
                    partz["operands"].append(bytez[tweak+offset+operoffset:offset+operoffset+osize])
                else:
                    partz["operands"].append("")

            operoffset += osize

        # Pull in the envi generic instruction flags
        iflags = iflag_lookup.get(optype, 0) | self._dis_oparch

        if prefixes & PREFIX_REP_MASK:
            iflags |= envi.IF_REPEAT

        if priv_lookup.get(mnem, False):
            iflags |= envi.IF_PRIV

        # Lea will have a reg-mem/sib operand with _is_deref True, but should be false
        if optype == opcode86.INS_LEA:
            operands[1]._is_deref = False

        ret = i386OpcodePartz(va, optype, mnem, prefixes, (offset-startoff)+operoffset, operands, iflags, partz)
        return ret

class i386OpcodePartz(i386Opcode):
    """Custom opcode class to hold the bytes we need"""
    def __init__(self, va, optype, mnem, prefixes, offset, operands, iflags, partz={}):
        # Old python style object
        i386Opcode.__init__(self, va, optype, mnem, prefixes, offset, operands, iflags)
        self.partz = partz

def binhex_spaced(inbin):
    """Format some data for a rule part"""
    return " ".join(["%02X" % ord(x) for x in inbin])

def yara_wildcard_instruction(ins):
    """For our custom instruction object, generate a wildcarded representation for consumption by Yara"""
    # Get our prefix and opcode parts in first
    p = binhex_spaced(ins.partz["prefix"])
    o = binhex_spaced(ins.partz["opcode"])
    opstring = ""

    for i in xrange(0, len(ins.opers)):
        # if its a mem, or mem reg, needs masking
        if isinstance(ins.opers[i], i386RegMemOper) or isinstance(ins.opers[i], i386ImmMemOper):
            # get target offset 
            target = 0
            if hasattr(ins.opers[i], 'disp'):
                target = ins.opers[i].disp
            elif hasattr(ins.opers[i], 'imm'):
                target = ins.opers[i].imm
                
            # Start off with 32-bit wide representation of target
            targetbytes = struct.pack("<L", target & 0xFFFFFFFF)
            basestr = ins.partz["operands"][i]
                
            # Trim out target bytes if we wrongly sized it (only support 8, 16, 32 bits for now)
            if len(basestr) < len(targetbytes) and len(basestr) in [1, 2, 4]:
                targetbytes = targetbytes[:len(basestr)]
                
            if targetbytes in basestr:
                # Add any preceding bytes
                opstring += binhex_spaced(basestr[0:basestr.find(targetbytes)])
                
                # Replace target with wildcard matches
                opstring += " " + "?? " * len(targetbytes)

                # And following bytes
                opstring += binhex_spaced(basestr[basestr.find(targetbytes)+len(targetbytes):])
            else:
                opstring += binhex_spaced(basestr)+ " "

        elif isinstance(ins.opers[i], i386RegOper):
            opstring += binhex_spaced(ins.partz["operands"][i])
        elif isinstance(ins.opers[i], i386ImmOper) or isinstance(ins.opers[i], i386ImmMemOper) or isinstance(ins.opers[i], i386PcRelOper):
            # Need to check if this is actually a reference to some memory (or code) (e.g. an offset);
            # We rely on IDA tracking references for this
            if idc.Dfirst(getattr(ins, 'imm', idc.BADADDR)) != idc.BADADDR or idc.Rfirst(getattr(ins, 'imm', idc.BADADDR)) != idc.BADADDR:
                # Got a data reference, its an immediate value so can mask the whole thing
                opstring += "?? " * len(ins.partz["operands"][i])
            else:
                # Not something to mask out, just add raw bytes
                opstring += binhex_spaced(ins.partz["operands"][i])
        else:
            # TODO: Do we want to mask any other operand types?
            # Any other operands, add the raw bytes
            opstring += binhex_spaced(ins.partz["operands"][i])

    return (" ".join([p, o, opstring])).lstrip()

# For debugging
def test_match(a, b):
    for i in xrange(0, min(len(a), len(b))):
        if a[i] != b[i] and "?" not in [a[i], b[i]]:
            return False
    return True


def yara_sig_code_selection():
    """Return some internal details for how we want to signature the selection"""
    cur_ea = SelStart()
    end_ea = SelEnd()
    d = i386DisasmParts()

    comments = []
    rulelines = []

    # Iterate over selected code bytes
    while cur_ea < end_ea:
        # Did we inadvertently select something that wasn't code?
        if not idc.isCode(idaapi.getFlags(cur_ea)):
            noncodebytes = "".join([chr(Byte(x)) for x in xrange(cur_ea, NextHead(cur_ea, end_ea))])
            comments.append("Non-code at %08X: %d bytes" % (cur_ea, len(noncodebytes)))
            rulelines.append(binhex_spaced(noncodebytes))
        else:
            curlen = idaapi.decode_insn(cur_ea)
            # Match IDA's disassembly format
            comments.append(GetDisasm(cur_ea))
            # But we need our custom object to process
            curbytes =  "".join([chr(Byte(b)) for b in xrange(cur_ea, cur_ea + curlen)])
            codefrag = d.disasm(curbytes, 0, cur_ea)
            rulelines.append(yara_wildcard_instruction(codefrag))

        # move along
        cur_ea = NextHead(cur_ea, end_ea)

    return (SelStart(), comments, rulelines)

def format_yara_code_sig_selection():
    """Format a rule fragment for use with Yara"""
    va, comments, rulelines = yara_sig_code_selection()
    outstring = ""
    varname = "$code_va_%08X" % va
    # Clean up any formatting boo boos while we're here
    rulestring = " ".join(rulelines).strip().replace("  "," ")
    m = rulestring
    outstring += "/* Code from starting VA %08x:\n" % va
    outstring += "\n".join(comments)
    
    # Can't end a match with wildcards
    if rulestring.endswith("??"):
        outstring += "\n(Truncated match)\n"
        while rulestring[-1] in [" ","?"]:
            rulestring = rulestring[:-1]
    
    outstring += "\n*/\n"
    outstring += "%s = { %s }\n" % (varname, rulestring)

    if DEBUG is True:
        print "DEBUG"

        r = " ".join(["%02X" % Byte(b) for b in xrange(SelStart(),SelEnd())])
        print "rulestring:", m
        print "raw:       ", r
        print "RESULT", test_match(m, r)
        print "-----"

    return outstring 



