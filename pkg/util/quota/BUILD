load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "quota.go",
        "quota_linux.go",
        "quota_unsupported.go",
    ],
    cgo = True,
    importpath = "k8s.io/kubernetes/pkg/util/quota",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/util/mount:go_default_library",
    ] + select({
        "@io_bazel_rules_go//go/platform:linux": [
            "//staging/src/k8s.io/apimachinery/pkg/util/uuid:go_default_library",
            "//vendor/golang.org/x/sys/unix:go_default_library",
            "//vendor/k8s.io/klog:go_default_library",
        ],
        "//conditions:default": [],
    }),
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
