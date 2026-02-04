"""
Typst PDF compile helper
"""

def _typst_pdf_impl(ctx):
    main = ctx.file.main
    typst = ctx.file._typst
    runner = ctx.executable._runner

    out = ctx.outputs.out
    if out == None:
        out = ctx.actions.declare_file(ctx.label.name + ".pdf")

    inputs = depset(
        direct = [main, ctx.info_file],
        transitive = [depset(ctx.files.srcs)],
    )

    ctx.actions.run(
        executable = runner,
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
        "_typst": attr.label(
            default = Label("//tools/typst:typst_bin"),
            allow_single_file = True,
            cfg = "exec",
        ),
        "_runner": attr.label(
            default = Label("//tools/typst:typst_compile_pdf"),
            executable = True,
            cfg = "exec",
        ),
    },
)
