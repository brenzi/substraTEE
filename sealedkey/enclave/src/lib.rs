// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "sealdatasampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate crypto;
extern crate rust_base58;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};
use sgx_tcrypto::*;
use std::vec::Vec;
use crypto::ed25519::keypair;
use rust_base58::{ToBase58, FromBase58};

//unsafe impl<'a> ContiguousMemory for RsaSecrets<'a> {}

#[no_mangle]
pub extern "C" fn create_sealed_key(sealed_seed: * mut u8, sealed_seed_size: u32, pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

    let mut seed = [0u8; 32];

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut seed);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8; 32]>::seal_data(&aad, &seed);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log(&sealed_data, sealed_seed, sealed_seed_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    //create ed25519 keypair
    let (privkey, pubkey) = keypair(&seed);
    println!("enclave generated sealed keyair with pubkey: {:?}", pubkey.to_base58());
    
    //println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealeddata(sealed_seed: * mut u8, sealed_seed_size: u32) -> sgx_status_t {

    let opt = from_sealed_log::<[u8; 32]>(sealed_seed, sealed_seed_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };


    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let seed = unsealed_data.get_decrypt_txt();
    //create ed25519 keypair
    let (privkey, pubkey) = keypair(seed);

    println!("enclave restored sealed keyair with pubkey: {:?}", pubkey.to_base58());

    sgx_status_t::SGX_SUCCESS
}

fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}