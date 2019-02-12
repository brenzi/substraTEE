extern crate wasmi;
use std::fs::File;
use wasmi::{ModuleInstance, Module, ImportsBuilder, NopExternals, RuntimeValue};

fn load_from_file(filename: &str) -> Module {
    use std::io::prelude::*;
    let mut file = File::open(filename).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    Module::from_buffer(buf).unwrap()
}

#[no_mangle]
fn get_offset() -> u32 {
    100
}
fn main() {
    
    let module = load_from_file("runtime.compact.wasm");

    // Instantiate a module with empty imports and
    // assert that there is no `start` function.
    let instance =
        ModuleInstance::new(
            &module,
            &ImportsBuilder::default()
        )
        .expect("failed to instantiate wasm module")
        .assert_no_start();
    // Finally, invoke the exported function "test" with no parameters
    // and empty external function executor.
    let result = instance.invoke_export(
        "add_one",
        &[RuntimeValue::I32(42)],
        &mut NopExternals,
    ).expect("failed to execute export");
    println!("return value = {:?}", result)
}
