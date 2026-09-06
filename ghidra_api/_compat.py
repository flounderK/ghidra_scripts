
def resolve_program(program):
    if program is not None:
        return program
    try:
        import __main__
        result = __main__.currentProgram
        if result is None:
            raise RuntimeError(
                "currentProgram is None. is a program open in Ghidra?"
            )
        return result
    except (ImportError, AttributeError):
        raise RuntimeError(
            "No program available. Pass program= explicitly "
            "or run inside a Ghidra script context."
        )


def resolve_monitor(monitor):
    if monitor is not None:
        return monitor
    try:
        import __main__
        return __main__.monitor
    except (ImportError, AttributeError):
        from ghidra.util.task import ConsoleTaskMonitor
        return ConsoleTaskMonitor()


def get_function_containing(program, addr):
    return program.getFunctionManager().getFunctionContaining(addr)


def get_memory_blocks(program):
    return list(program.getMemory().getBlocks())


def get_bytes(program, addr, size):
    try:
        import jarray
        buf = jarray.zeros(size, 'b')
    except ImportError:
        import jpype
        buf = jpype.JArray(jpype.JByte)(size)
    program.getMemory().getBytes(addr, buf)
    return buf


def get_references_to(program, addr):
    return program.getReferenceManager().getReferencesTo(addr)


def get_references_from(program, addr):
    return program.getReferenceManager().getReferencesFrom(addr)


def to_addr(program, offset):
    if isinstance(offset, str):
        return program.getAddressFactory().getAddress(offset)
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    return addr_space.getAddress(offset)


def get_function_at(program, addr):
    return program.getFunctionManager().getFunctionAt(addr)


def run_command(program, cmd):
    tx_id = program.startTransaction(cmd.getName())
    try:
        success = cmd.applyTo(program)
        program.endTransaction(tx_id, success)
        return success
    except Exception:
        program.endTransaction(tx_id, False)
        raise
