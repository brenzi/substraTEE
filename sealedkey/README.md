# Sealed Key Example

A simple example that lets the enclave generate a sealed seed.
Based on the seed, the enclave derives a ed25519 keypair and returns the public key to the client.
The client can send a message to the enclave to be signed with above key
The signature is verified.

run:
```
> make
> cd bin
> ./app
[+] Home dir is /home/brenzi
[+] Open token file success! 
[+] Token file invalid, will create new token file
[+] Init Enclave Successful 2!
enclave generated sealed keyair with pubkey: "BnQek3JGZgWaDQ38DeYemdrGb3kkbUk6wBYQKkFxcEfH"
[+] enclave returned pubkey: "BnQek3JGZgWaDQ38DeYemdrGb3kkbUk6wBYQKkFxcEfH"
let enclave sign message: This message is true
enclave restored sealed keyair with pubkey: "BnQek3JGZgWaDQ38DeYemdrGb3kkbUk6wBYQKkFxcEfH"
[+] enclave signature is correct!
```