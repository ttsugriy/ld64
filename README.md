# ld64
Latest version of Mac OS static linker sources with some modifications to make it buildable outside Apple.

Since produced `ld` binary is linked with `@rpath/libLTO.dylib` in using `-lazy_library`, it's important to use `LD_LIBRARY_PATH` environment variable pointing to a directory where `libLTO.dylib` lives.
