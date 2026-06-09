"""Repository helpers for Typst toolchains."""

_TYPST_PLATFORMS = {
    "linux_aarch64": struct(
        repo = "typst_linux_aarch64",
        archive = "typst-aarch64-unknown-linux-musl",
        compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:aarch64",
        ],
    ),
    "linux_x86_64": struct(
        repo = "typst_linux_x86_64",
        archive = "typst-x86_64-unknown-linux-musl",
        compatible_with = [
            "@platforms//os:linux",
            "@platforms//cpu:x86_64",
        ],
    ),
}

_TYPST_RELEASES = {
    "0.14.2": {
        "linux_aarch64": "491b101aa40a3a7ea82a3f8a6232cabb4e6a7e233810082e5ac812d43fdcd47a",
        "linux_x86_64": "a6044cbad2a954deb921167e257e120ac0a16b20339ec01121194ff9d394996d",
    },
}

def typst_platforms():
    return _TYPST_PLATFORMS

def typst_release(version):
    if version not in _TYPST_RELEASES:
        fail("Unsupported Typst version '{}'. Supported versions: {}".format(
            version,
            ", ".join(sorted(_TYPST_RELEASES.keys())),
        ))
    return _TYPST_RELEASES[version]

def typst_archive_build_file():
    return """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "typst_bin",
    srcs = ["typst"],
)
"""

def _typst_toolchains_repo_impl(rctx):
    lines = [
        'load("@{}//tools/typst:toolchain.bzl", "typst_toolchain")'.format(rctx.attr.root_module_name),
        "",
        'package(default_visibility = ["//visibility:public"])',
        "",
    ]

    for name, platform in sorted(_TYPST_PLATFORMS.items()):
        lines.extend([
            "typst_toolchain(",
            '    name = "{}_impl",'.format(name),
            '    typst = "@{}//:typst_bin",'.format(platform.repo),
            ")",
            "",
            "toolchain(",
            '    name = "{}",'.format(name),
            "    exec_compatible_with = [",
        ])
        for constraint in platform.compatible_with:
            lines.append('        "{}",'.format(constraint))
        lines.extend([
            "    ],",
            '    toolchain = ":{}_impl",'.format(name),
            '    toolchain_type = "@{}//tools/typst:toolchain_type",'.format(rctx.attr.root_module_name),
            ")",
            "",
        ])

    rctx.file("BUILD.bazel", "\n".join(lines))

typst_toolchains_repo = repository_rule(
    implementation = _typst_toolchains_repo_impl,
    attrs = {
        "root_module_name": attr.string(mandatory = True),
    },
)
