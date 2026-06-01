"""Typst PDF compile helper"""

_TOOLCHAIN_TYPE = "//tools/typst:toolchain_type"

def _typst_pdf_impl(ctx):
    main = ctx.file.main
    typst = ctx.toolchains[_TOOLCHAIN_TYPE].typst

    out = ctx.outputs.out
    if out == None:
        out = ctx.actions.declare_file(ctx.label.name + ".pdf")

    inputs = depset(
        direct = [main, ctx.info_file],
        transitive = [depset(ctx.files.srcs)],
    )

    ctx.actions.run_shell(
        command = """
set -euo pipefail

readonly typst="$1"
readonly version_file="$2"
readonly pdf_standard="$3"
readonly main="$4"
readonly out="$5"

readonly ts="$(awk '$1=="STABLE_GIT_TIMESTAMP"{print $2; exit}' "$version_file" || true)"
if [[ -z "${ts:-}" ]]; then
    echo "ERROR: STABLE_GIT_TIMESTAMP missing" >&2
    exit 1
fi

exec "$typst" compile \
    --format pdf \
    --ignore-system-fonts \
    --creation-timestamp "$ts" \
    --pdf-standard "$pdf_standard" \
    "$main" \
    "$out"
""",
        tools = [typst],
        inputs = inputs,
        outputs = [out],
        arguments = [
            typst.path,
            ctx.info_file.path,
            ctx.attr.pdf_standard,
            main.path,
            out.path,
        ],
        mnemonic = "TypstPdf",
        progress_message = "Compiling Typst PDF %s" % out.short_path,
    )

    return [DefaultInfo(files = depset([out]))]

typst_pdf = rule(
    implementation = _typst_pdf_impl,
    attrs = {
        "main": attr.label(mandatory = True, allow_single_file = [".typ"]),
        "srcs": attr.label_list(allow_files = True),
        "pdf_standard": attr.string(default = "1.7"),
        "out": attr.output(mandatory = False),
    },
    toolchains = [_TOOLCHAIN_TYPE],
)
