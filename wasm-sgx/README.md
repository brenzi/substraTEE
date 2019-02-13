# Running WASM binary within SGX

This example is derived from [rust-sgx-sdk](https://github.com/baidu/rust-sgx-sdk).

Here we build our own very simple wasm runtime in rust:
```
> cd runtime
> ./build.sh
> cd ..
```
And run that wasm within WASMI within SGX:
```
> make
> cd bin
> ./app
[+] Home dir is /home/brenzi
[+] Open token file success! 
[+] Token file invalid, will create new token file
[+] Init Enclave Successful 2!
[+] Init Wasm in Enclave Successful
[Enclave] sgxwasm_run_action() called
[Enclave] wasm_invoke successful
[Enclave] result_covert successful
[Enclave] serialization successful
result: Ok(Some(I32(43)))
[+] run_wasm success...
```

# TODO
1. Clean up unnecessary code from original example
2. add runtime build to makefile
2. Allow to pass arbitrary types to wasm (now only i32,i64,f32,f64 are supported). How?

