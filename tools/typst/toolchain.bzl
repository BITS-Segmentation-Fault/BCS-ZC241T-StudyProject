"""Typst toolchain definitions."""

def _typst_toolchain_impl(ctx):
    return [
        platform_common.ToolchainInfo(
            typst = ctx.file.typst,
        ),
    ]

typst_toolchain = rule(
    implementation = _typst_toolchain_impl,
    attrs = {
        "typst": attr.label(
            allow_single_file = True,
            executable = True,
            cfg = "exec",
            mandatory = True,
        ),
    },
)
