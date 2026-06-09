"""Typst bzlmod extension."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load(
    "//tools/typst:repositories.bzl",
    "typst_archive_build_file",
    "typst_platforms",
    "typst_release",
    "typst_toolchains_repo",
)

def _typst_impl(module_ctx):
    root_module = None
    version = None

    for mod in module_ctx.modules:
        if mod.is_root:
            root_module = mod
            for toolchain in mod.tags.toolchain:
                if version and version != toolchain.version:
                    fail("Only one Typst toolchain version can be configured")
                version = toolchain.version

    if not root_module:
        fail("Typst toolchains must be configured from the root module")
    if not version:
        fail('Missing typst.toolchain(version = "...") in MODULE.bazel')

    release = typst_release(version)
    platforms = typst_platforms()

    for name, platform in sorted(platforms.items()):
        http_archive(
            name = platform.repo,
            build_file_content = typst_archive_build_file(),
            sha256 = release[name],
            strip_prefix = platform.archive,
            urls = [
                "https://github.com/typst/typst/releases/download/v{version}/{archive}.tar.xz".format(
                    archive = platform.archive,
                    version = version,
                ),
            ],
        )

    typst_toolchains_repo(
        name = "typst_toolchains",
        root_module_name = root_module.name,
    )

_toolchain = tag_class(
    attrs = {
        "version": attr.string(mandatory = True),
    },
)

typst = module_extension(
    implementation = _typst_impl,
    tag_classes = {
        "toolchain": _toolchain,
    },
)
