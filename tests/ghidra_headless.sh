# Shared headless launcher for this repo's test suites. Source it, then call
# ghidra_headless with the usual analyzeHeadless arguments.
#
# The repo supports both of Ghidra's Python runtimes, and which one an install
# can actually run differs by version: Jython was bundled through 11.x and
# became an installable extension in 12, while PyGhidra (CPython) is bundled
# from 11.2 on but has to be launched through its own entry point rather than
# analyzeHeadless. This picks whichever the install has, and lets either be
# forced so both can be exercised.
#
#   GHIDRA_DIR      install to use                  (default /opt/ghidra)
#   GHIDRA_RUNTIME  jython | pyghidra | auto        (default auto)

GHIDRA_DIR="${GHIDRA_DIR:-/opt/ghidra}"
GHIDRA_RUNTIME="${GHIDRA_RUNTIME:-auto}"

ghidra_has_jython() {
    [ -f "$GHIDRA_DIR/Ghidra/Features/Jython/lib/Jython.jar" ] && return 0
    # installed as an extension (Ghidra 12 ships the zip but does not install it)
    ls "$GHIDRA_DIR"/Ghidra/Extensions/*/lib/Jython.jar >/dev/null 2>&1
}

ghidra_runtime() {
    case "$GHIDRA_RUNTIME" in
        jython|pyghidra) printf '%s\n' "$GHIDRA_RUNTIME" ;;
        auto)
            if ghidra_has_jython; then printf 'jython\n'; else printf 'pyghidra\n'; fi ;;
        *)
            echo "GHIDRA_RUNTIME must be jython, pyghidra or auto" >&2
            return 1 ;;
    esac
}

ghidra_headless() {
    local runtime
    runtime="$(ghidra_runtime)" || return 1
    echo "[*] $(basename "$GHIDRA_DIR") via $runtime" >&2
    if [ "$runtime" = "jython" ]; then
        "$GHIDRA_DIR/support/analyzeHeadless" "$@"
    else
        # analyzeHeadless cannot start PyGhidra itself; ghidra_launch boots the
        # JVM with it already initialised and then hands over to the same class.
        GHIDRA_INSTALL_DIR="$GHIDRA_DIR" python3 -m pyghidra.ghidra_launch \
            --install-dir "$GHIDRA_DIR" \
            ghidra.app.util.headless.AnalyzeHeadless "$@"
    fi
}
