fn main() {
    cxx_build::bridge("src/lib.rs")
        .file("Include/Driver.cpp")
        .include("../KernelDriver/include")
        .include("../KernelDriver/atlmfc/include")
        .cpp(true)
        .flag("/std:c++17")
        .flag("/DUNICODE")
        .flag("/INCREMENTAL")
        .compile("driver");
}