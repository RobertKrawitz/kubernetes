load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "go_default_library",
    srcs = [
        "quota.go",
        "quota_linux.go",
        "quota_unsupported.go",
    ],
    importpath = "k8s.io/kubernetes/pkg/util/quota",
    visibility = ["//visibility:public"],
    deps = [
        "//vendor/github.com/golang/glog:go_default_library",
        "//vendor/k8s.io/utils/exec:go_default_library",
    ] + select({
        "@io_bazel_rules_go//go/platform:android": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:darwin": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:dragonfly": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:freebsd": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "//pkg/util/file:go_default_library",
            "//pkg/util/io:go_default_library",
            "//pkg/util/nsenter:go_default_library",
            "//staging/src/k8s.io/apimachinery/pkg/util/sets:go_default_library",
            "//vendor/golang.org/x/sys/unix:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:nacl": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:netbsd": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:openbsd": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:plan9": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:solaris": [
            "//pkg/util/nsenter:go_default_library",
        ],
        "@io_bazel_rules_go//go/platform:windows": [
            "//pkg/util/file:go_default_library",
            "//pkg/util/nsenter:go_default_library",
        ],
        "//conditions:default": [],
    }),
)
