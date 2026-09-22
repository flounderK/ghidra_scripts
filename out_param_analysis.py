from ghidra_api.call_ref_utils import get_callsites_for_func_by_name
from collections import defaultdict
from ghidra_api._compat import resolve_program, same_java_object
from ghidra_api.decomp_utils import DecompUtils
from ghidra.program.model.pcode import PcodeOpAST
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra_api.register_utils import getStackRegister
import logging

log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.WARNING)


class _SinkDesc(object):
    """
    Base for a description of a buffer-writing sink: the name to find calls
    to, the per-caller result buckets, and cached callsite lookup. Subclasses
    add the model-specific fields (fixed parameter indexes, or a format string
    to parse) and drive how a single call is classified.
    """

    def __init__(self, func_name):
        self.func_name = func_name
        self._callsites = None
        self._callsites_program = None
        # memcpy_s
        self.stack_dest_var_dest_size_by_func = defaultdict(set)
        # memcpy or strcpy
        self.stack_dest_var_or_no_src_size_by_func = defaultdict(set)
        # memcpy or strcpy, but could lead to an info leak
        self.stack_src_var_or_no_src_size_by_func = defaultdict(set)
        # all param: needs additional analysis
        self.all_params_var_by_func = defaultdict(set)
        # possible overflow in a global
        self.const_dest_var_or_no_src_size_by_func = defaultdict(set)
        # a scanf-family call whose format string could not be resolved to a
        # constant: a non-constant scanf format is itself a bug worth review
        self.dynamic_format_by_func = defaultdict(set)
        # mapping of which parameter indexes are sourced from the caller functions parameters
        # caller func: {call_addr: [(func_name param no, caller_func param no),]}
        self.param_to_caller_param_map = defaultdict(dict)

    def get_callsites(self, program=None):
        """
        Return {Function: [call address, ..]} for calls to this function,
        looked up once per program and cached. An empty result is cached too,
        since the lookup scans every function in the program
        """
        if (self._callsites is None or
                not same_java_object(self._callsites_program, program)):
            self._callsites = get_callsites_for_func_by_name(self.func_name, program=program)
            self._callsites_program = program
        return self._callsites

    @property
    def callsites(self):
        return self.get_callsites()


class FuncOutParamAnalysisDesc(_SinkDesc):
    def __init__(self, func_name, out_param_no=None, src_size_param_no=None, dest_size_param_no=None, src_param_no=None):
        super(FuncOutParamAnalysisDesc, self).__init__(func_name)
        self.out_param_no = out_param_no
        self.src_size_param_no = src_size_param_no
        self.dest_size_param_no = dest_size_param_no
        self.src_param_no = src_param_no


class FormatWriteDesc(_SinkDesc):
    """
    A scanf-family sink whose output buffers are variadic arguments selected by
    the format string. @fmt_param_no is the 1-based argument position of the
    format string, and @vararg_start_no is the position of the first variadic
    argument (usually fmt_param_no + 1). The destination for the Nth
    arg-consuming conversion in the format is argument @vararg_start_no + N.
    """

    def __init__(self, func_name, fmt_param_no, vararg_start_no=None):
        super(FormatWriteDesc, self).__init__(func_name)
        self.fmt_param_no = fmt_param_no
        self.vararg_start_no = (vararg_start_no if vararg_start_no is not None
                                else fmt_param_no + 1)


class OutParamAnalysisCollection(object):
    def __init__(self, analysis_descs=None):
        # a list of sink descriptors (FuncOutParamAnalysisDesc or FormatWriteDesc)
        self.analysis_descs = analysis_descs if analysis_descs is not None else []

    def get_calling_func_to_desc_map(self, program=None):
        """
        Return a mapping of calling func to the sink descriptors with callsites in it
        """
        res = defaultdict(list)
        for desc in self.analysis_descs:
            for calling_func in desc.get_callsites(program=program).keys():
                res[calling_func].append(desc)
        return dict(res)


class CallParamAttributes(object):
    """
    Attributes of a single call, gathered from the parameters we care about
    """

    __slots__ = ("stack_dest", "stack_src", "const_or_addr_dest",
                 "var_dest_size", "var_src_size", "var_dest", "var_src")

    def __init__(self, desc):
        self.stack_dest = False
        self.stack_src = False
        self.const_or_addr_dest = False
        self.var_dest_size = False
        # variable src size can be considered to be true if it isn't existent
        # because that means that the size is inferred
        self.var_src_size = desc.src_size_param_no is None
        self.var_dest = False
        self.var_src = desc.src_param_no is None


def _is_stack_derived(varnode, stack_reg_offset):
    """
    True if @varnode is reached from the stack pointer register
    """
    back_slice_vns = DecompilerUtils.getBackwardSlice(varnode)
    return any([vn for vn in back_slice_vns
                if vn.isRegister() and int(vn.getOffset()) == stack_reg_offset])


def _get_call_input(op, param_no):
    """
    Return input @param_no of the call @op, or None if it is out of range.

    A CALL op's inputs are input[0] (the call target) followed by the recovered
    parameters, so a parameter index is only valid when it is below
    getNumInputs(). Ghidra's PcodeOp.getInput indexes a raw array without a
    bounds check, so an index past the parameters the decompiler recovered for
    this callsite raises ArrayIndexOutOfBoundsException. Callsites vary in how
    completely their signatures are recovered, so guarding here is what lets the
    analysis run across many functions instead of aborting on the first call
    with a short parameter list.
    """
    if param_no is None or param_no >= op.getNumInputs():
        return None
    return op.getInput(param_no)


def get_call_param_attributes(op, desc, stack_reg_offset):
    """
    Gather attribute info about the call @op and the parameters to it that we
    care about, as described by @desc
    """
    attrs = CallParamAttributes(desc)

    if desc.src_size_param_no is not None:
        inp = _get_call_input(op, desc.src_size_param_no)
        if inp is not None:
            if inp.isConstant() is False:
                attrs.var_src_size = True

    if desc.dest_size_param_no is not None:
        inp = _get_call_input(op, desc.dest_size_param_no)
        if inp is not None:
            if inp.isConstant() is False:
                attrs.var_dest_size = True

    if desc.src_param_no is not None:
        inp = _get_call_input(op, desc.src_param_no)
        if inp is not None:
            # TODO: an addr src from a rw region is still useful if size is not const
            if not (inp.isConstant() is True or inp.isAddress() is True):
                attrs.var_src = True
            if _is_stack_derived(inp, stack_reg_offset):
                attrs.stack_src = True

    if desc.out_param_no is not None:
        inp = _get_call_input(op, desc.out_param_no)
        if inp is not None:
            if inp.isConstant() is True or inp.isAddress() is True:
                attrs.const_or_addr_dest = True
            else:
                attrs.var_dest = True
            if _is_stack_derived(inp, stack_reg_offset):
                attrs.stack_dest = True

    return attrs


def record_call(desc, calling_func, call_addr, attrs):
    """
    Group the call at @call_addr based on the attributes gathered for it
    """
    # memcpy_s
    if attrs.stack_dest and attrs.var_dest_size:
        desc.stack_dest_var_dest_size_by_func[calling_func].add(call_addr)

    # memcpy or strcpy
    if attrs.stack_dest and attrs.var_src_size:
        desc.stack_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)

    # memcpy or strcpy, but could lead to an info leak
    if attrs.stack_src and attrs.var_src_size:
        desc.stack_src_var_or_no_src_size_by_func[calling_func].add(call_addr)

    # all param: needs additional analysis
    if attrs.var_dest and attrs.var_src_size and attrs.var_src and \
            (desc.dest_size_param_no is None or attrs.var_dest_size is True):
        desc.all_params_var_by_func[calling_func].add(call_addr)

    # possible overflow in a global
    if attrs.const_or_addr_dest and attrs.var_src_size:
        desc.const_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)


# conversion characters that consume a pointer argument and write bytes into
# the buffer it points at
_SCANF_WRITE_CONVS = frozenset("sc[")
# length modifier characters that may sit between the width and the conversion
_SCANF_LENGTH_MODS = frozenset("hljztLq")


def _parse_scanf_conversions(fmt):
    """
    Parse a scanf-family format string into the ordered list of conversions
    that consume a variadic pointer argument.

    Each entry is a dict with:
      arg_index: 0-based position of this conversion among arg-consuming ones,
                 which fixes which variadic argument it writes to
      is_write:  True for %s / %[ / %c, which write bytes through the pointer
      width:     the field width if one was given, else None
      unbounded: True for a write conversion with no field width (%s / %[),
                 i.e. the classic unbounded case

    Assignment-suppressed conversions (%*...) consume input but no argument and
    so are skipped; %% is a literal.
    """
    convs = []
    i = 0
    n = len(fmt)
    arg_index = 0
    while i < n:
        if fmt[i] != '%':
            i += 1
            continue
        i += 1
        if i >= n:
            break
        if fmt[i] == '%':
            i += 1
            continue
        suppress = False
        if fmt[i] == '*':
            suppress = True
            i += 1
        wstart = i
        while i < n and fmt[i].isdigit():
            i += 1
        width = int(fmt[wstart:i]) if i > wstart else None
        while i < n and fmt[i] in _SCANF_LENGTH_MODS:
            i += 1
        if i >= n:
            break
        conv = fmt[i]
        if conv == '[':
            # scanset runs to the next ']', except a ']' or '^]' right after
            # the '[' is a member, not the terminator
            i += 1
            if i < n and fmt[i] == '^':
                i += 1
            if i < n and fmt[i] == ']':
                i += 1
            while i < n and fmt[i] != ']':
                i += 1
            i += 1  # step past the closing ']'
        else:
            i += 1
        if suppress:
            continue
        is_write = conv in _SCANF_WRITE_CONVS
        convs.append({
            "arg_index": arg_index,
            "is_write": is_write,
            "width": width,
            # %c writes exactly `width` (default 1) bytes and is bounded; only
            # %s / %[ with no width are the unbounded overflow case
            "unbounded": is_write and conv != 'c' and width is None,
        })
        arg_index += 1
    return convs


def _read_c_string(program, offset, max_len=4096):
    """
    Read a NUL-terminated printable string at @offset from program memory, or
    None if @offset is not mapped or the bytes are not a plain string
    """
    mem = program.getMemory()
    space = program.getAddressFactory().getDefaultAddressSpace()
    try:
        addr = space.getAddress(offset)
    except Exception:
        return None
    out = []
    for i in range(max_len):
        try:
            b = mem.getByte(addr.add(i)) & 0xff
        except Exception:
            return None
        if b == 0:
            return "".join(out)
        if b < 0x09 or b > 0x7e:
            return None
        out.append(chr(b))
    return None


def _resolve_format_string(varnode, program):
    """
    Resolve @varnode to the constant string it points at, following the
    backward slice since the pointer is usually materialized by a COPY/PTRSUB
    of a constant address rather than being a constant itself. Returns None
    when no constant string source can be found (a dynamic format string)
    """
    candidates = [varnode]
    try:
        candidates += list(DecompilerUtils.getBackwardSlice(varnode))
    except Exception:
        pass
    for vn in candidates:
        if vn.isConstant() or vn.isAddress():
            s = _read_c_string(program, vn.getOffset())
            if s is not None:
                return s
    return None


def analyze_format_call(op, desc, calling_func, call_addr, stack_reg_offset, program):
    """
    Classify a single scanf-family call: resolve its format string, then for
    each unbounded string conversion check where its destination buffer lives
    and record it in the same buckets the fixed-parameter analysis uses
    """
    fmt_vn = _get_call_input(op, desc.fmt_param_no)
    if fmt_vn is None:
        return
    fmt = _resolve_format_string(fmt_vn, program)
    if fmt is None:
        desc.dynamic_format_by_func[calling_func].add(call_addr)
        return

    for conv in _parse_scanf_conversions(fmt):
        if not conv["is_write"]:
            continue
        dest_vn = _get_call_input(op, desc.vararg_start_no + conv["arg_index"])
        if dest_vn is None:
            # fewer args recovered than the format calls for; nothing to judge
            continue
        stack_dest = _is_stack_derived(dest_vn, stack_reg_offset)
        const_or_addr_dest = dest_vn.isConstant() or dest_vn.isAddress()
        if conv["unbounded"]:
            # unbounded %s / %[ into a fixed buffer: the classic overflow
            if stack_dest:
                desc.stack_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)
            if const_or_addr_dest:
                desc.const_dest_var_or_no_src_size_by_func[calling_func].add(call_addr)
            if not const_or_addr_dest and not stack_dest:
                desc.all_params_var_by_func[calling_func].add(call_addr)
        else:
            # width-bounded (%Ns) or single-char (%c): surface for review, since
            # whether the width exceeds the buffer still needs a look
            desc.all_params_var_by_func[calling_func].add(call_addr)


def _get_call_ops_by_target(du, calling_func):
    """
    Return {call target address: [PcodeOpAST, ..]} for the CALL ops in
    @calling_func, or None if it could not be decompiled
    """
    pcode_ops = du.get_pcode_for_function(calling_func)
    if pcode_ops is None:
        return None
    call_ops_by_target = defaultdict(list)
    for op in pcode_ops:
        if op.opcode == PcodeOpAST.CALL:
            call_ops_by_target[op.seqnum.target].append(op)
    return call_ops_by_target


def out_param_analysis(desc_col, program=None):
    """
    OutParamAnalysisCollection
    """
    program = resolve_program(program)
    stack_reg_offset = getStackRegister(program=program).getOffset()
    du = DecompUtils(program=program)
    for calling_func, descs in desc_col.get_calling_func_to_desc_map(program=program).items():
        # decompile each calling function once, no matter how many descs it
        # has callsites for
        call_ops_by_target = _get_call_ops_by_target(du, calling_func)
        if call_ops_by_target is None:
            log.warning("skipping %s, no pcode available" % calling_func.name)
            continue
        for desc in descs:
            for call_addr in desc.get_callsites(program=program)[calling_func]:
                for op in call_ops_by_target.get(call_addr, []):
                    if isinstance(desc, FormatWriteDesc):
                        analyze_format_call(op, desc, calling_func, call_addr,
                                            stack_reg_offset, program)
                    else:
                        attrs = get_call_param_attributes(op, desc, stack_reg_offset)
                        record_call(desc, calling_func, call_addr, attrs)

    return desc_col


def single_out_param_analysis(func_name, out_param_no, src_size_param_no=None, dest_size_param_no=None, src_param_no=None, program=None):
    opar = FuncOutParamAnalysisDesc(func_name, out_param_no, src_size_param_no, dest_size_param_no, src_param_no)
    out_param_analysis(OutParamAnalysisCollection([opar]), program=program)
    return opar


desc_col = OutParamAnalysisCollection()
desc_col.analysis_descs = [
    FuncOutParamAnalysisDesc("memcpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("memmove", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("wmemmove", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("wmemcpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("memcpy_s", out_param_no=1,
                             src_size_param_no=4,
                             dest_size_param_no=2, src_param_no=3),
    FuncOutParamAnalysisDesc("wmemcpy_s", out_param_no=1,
                             src_size_param_no=4,
                             dest_size_param_no=2, src_param_no=3),
    FuncOutParamAnalysisDesc("strcpy", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("strncpy", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    FuncOutParamAnalysisDesc("sprintf", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=None,
                             src_param_no=None),
    FuncOutParamAnalysisDesc("snprintf", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=2,
                             src_param_no=None),
    # strcat(dest, src): unbounded append, like strcpy
    FuncOutParamAnalysisDesc("strcat", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=None, src_param_no=2),
    # strncat(dest, src, n): n bounds the copy, not the dest capacity
    FuncOutParamAnalysisDesc("strncat", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=2),
    # read(fd, buf, count): buf is arg 2; count is how many bytes get written
    FuncOutParamAnalysisDesc("read", out_param_no=2,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=None),
    # recv(fd, buf, len, flags): buf is arg 2, len is the write size
    FuncOutParamAnalysisDesc("recv", out_param_no=2,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=None),
    # recvfrom(fd, buf, len, flags, src_addr, addrlen): buf is arg 2
    FuncOutParamAnalysisDesc("recvfrom", out_param_no=2,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=None),
    # fread(ptr, size, nmemb, stream): true size is size*nmemb, which the
    # single-index model cannot express; nmemb (arg 3) approximates it
    FuncOutParamAnalysisDesc("fread", out_param_no=1,
                             src_size_param_no=3,
                             dest_size_param_no=None, src_param_no=None),
    # readlink(path, buf, bufsiz): buf is arg 2, bufsiz bounds it; result is
    # not NUL-terminated, so a full write is already an off-by-one risk
    FuncOutParamAnalysisDesc("readlink", out_param_no=2,
                             src_size_param_no=None,
                             dest_size_param_no=3, src_param_no=None),
    # fgets(buf, size, stream): size bounds the write; only interesting when
    # size is a variable that can exceed the buffer
    FuncOutParamAnalysisDesc("fgets", out_param_no=1,
                             src_size_param_no=None,
                             dest_size_param_no=2, src_param_no=None),
    # scanf family: the output buffers are variadic args picked out by the
    # format string, so these are parsed rather than described by fixed indexes.
    # glibc emits the __isoc99_ variants; the plain names cover other libcs.
    # sscanf(str, fmt, ...): fmt is arg 2, first output is arg 3
    FormatWriteDesc("sscanf", fmt_param_no=2),
    FormatWriteDesc("__isoc99_sscanf", fmt_param_no=2),
    # fscanf(stream, fmt, ...): fmt is arg 2, first output is arg 3
    FormatWriteDesc("fscanf", fmt_param_no=2),
    FormatWriteDesc("__isoc99_fscanf", fmt_param_no=2),
    # scanf(fmt, ...): fmt is arg 1, first output is arg 2
    FormatWriteDesc("scanf", fmt_param_no=1),
    FormatWriteDesc("__isoc99_scanf", fmt_param_no=1),
]
