uniffi-bindgen-go bindings/ldk_node.udl -o ffi/golang -c ./uniffi.toml || exit 1
cargo build --lib --all-features --release || exit 1
cp ./target/release/libldk_node.so ffi/golang/ldk_node