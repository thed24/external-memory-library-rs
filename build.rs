fn main() {
    cxx_build::bridge("src/lib.rs")
        .file("include/Driver.cpp")
        .include("../KernelDriver/include")
        .include("../KernelDriver/atlmfc/include")
        .cpp(true)
        .flag_if_supported("/std:c++17")
        .flag_if_supported("/DUNICODE")
        .flag_if_supported("/INCREMENTAL")
        .compile("driver");
}
