# WASM test

Do Rust(Wasm(Rust)):

* implement a simple function in rust and build it as wasm
* implement rust binary that runs WASMI that runs our above module

## build
```
cd runtime
./build.sh
cd ..
cargo build --release
./target/release/wasm-test
```
result should be 
```
return value = Some(I32(43))
```