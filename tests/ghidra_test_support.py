#@runtime Jython
"""
Shared support for the ghidra_api test suites.

Test modules define functions named test_* taking a single TestRun argument:

    def test_something(t):
        t.equal("descriptive name", actual, expected)

run_modules() imports each module, runs every test_* function it finds, and
isolates failures: a Java exception in one test is reported and the rest of
the suite still runs. That matters here because Ghidra throws Java
exceptions, which do not derive from Python's Exception under Jython.
"""

import traceback

try:
    from java.lang import Exception as JavaException
    CAUGHT_ERRORS = (Exception, JavaException)
except:  # noqa: E722 - must not itself use `except Exception`
    CAUGHT_ERRORS = (Exception,)


class TestRun(object):
    """Collects check results for one suite run."""

    def __init__(self, verbose=True):
        self.results = []
        self.verbose = verbose
        self._module = "?"

    def _record(self, name, ok, detail):
        self.results.append((self._module, name, ok, detail))
        if self.verbose:
            print("[%s] %s.%s%s" % ("PASS" if ok else "FAIL", self._module,
                                    name, (" -- " + detail) if detail else ""))

    def check(self, name, condition, detail=""):
        self._record(name, bool(condition), detail)
        return bool(condition)

    def equal(self, name, actual, expected):
        return self.check(name, actual == expected,
                          "" if actual == expected
                          else "got %r, expected %r" % (actual, expected))

    def not_equal(self, name, actual, unexpected):
        return self.check(name, actual != unexpected,
                          "" if actual != unexpected else "both %r" % (actual,))

    def not_none(self, name, value):
        return self.check(name, value is not None, "" if value is not None else "got None")

    def contains(self, name, container, member):
        ok = member in container
        return self.check(name, ok, "" if ok else "%r not in %r" % (member, container))

    def raises(self, name, exc_types, callable_, *args, **kwargs):
        try:
            callable_(*args, **kwargs)
        except exc_types:
            return self.check(name, True)
        except CAUGHT_ERRORS as exc:
            return self.check(name, False, "raised %s instead" % type(exc).__name__)
        return self.check(name, False, "did not raise")

    @property
    def failures(self):
        return [(m, n, d) for m, n, ok, d in self.results if not ok]

    @property
    def passed(self):
        return len(self.results) - len(self.failures)


def run_module(module, run):
    """Run every test_* function in @module against @run."""
    run._module = getattr(module, "__name__", "?").split(".")[-1]
    names = sorted(n for n in dir(module) if n.startswith("test_"))
    setup = getattr(module, "setup_module", None)
    context = None
    if setup is not None:
        try:
            context = setup()
        except CAUGHT_ERRORS:
            run.check("setup_module", False, traceback.format_exc().strip().replace("\n", " | "))
            return
    for name in names:
        func = getattr(module, name)
        if not callable(func):
            continue
        try:
            if context is None:
                func(run)
            else:
                func(run, context)
        except CAUGHT_ERRORS:
            # one broken test must not take the rest of the suite with it
            run.check(name, False,
                      "raised: " + traceback.format_exc().strip().replace("\n", " | ")[-300:])


def run_modules(module_names, package=None):
    """Import and run each named test module. Returns the TestRun."""
    run = TestRun()
    for name in module_names:
        full = "%s.%s" % (package, name) if package else name
        try:
            module = __import__(full, globals(), locals(), ["*"])
        except CAUGHT_ERRORS:
            run._module = name
            run.check("import", False,
                      traceback.format_exc().strip().replace("\n", " | ")[-300:])
            continue
        run_module(module, run)
    return run


def report(run):
    """Print a summary. Returns True when everything passed."""
    print("")
    print("%d/%d checks passed" % (run.passed, len(run.results)))
    if run.failures:
        for module, name, detail in run.failures:
            print("  FAILED %s.%s%s" % (module, name, (" -- " + detail) if detail else ""))
        print("SOME TESTS FAILED")
        return False
    print("ALL TESTS PASSED")
    return True


# --- fixture lookup helpers -------------------------------------------------
# Shared so each test module does not re-implement them.


def get_function(program, name):
    """The (non-thunk, non-external) function called @name, or None."""
    for func in program.getFunctionManager().getFunctions(True):
        if func.getName() == name and not func.isThunk() and not func.isExternal():
            return func
    return None


def find_type(dtm, name):
    """The datatype called @name, whatever category it was filed under."""
    for datatype in dtm.getAllDataTypes():
        if datatype.getName() == name:
            return datatype
    return None


def global_address(program, symbol_name):
    """The address of the global symbol @symbol_name, or None."""
    for symbol in program.getSymbolTable().getGlobalSymbols(symbol_name):
        return symbol.getAddress()
    return None


def global_data(program, symbol_name):
    """The defined Data at global @symbol_name, or None."""
    address = global_address(program, symbol_name)
    if address is None:
        return None
    return program.getListing().getDataAt(address)
