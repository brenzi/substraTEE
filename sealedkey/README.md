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
[Enclave] generated sealed keyair with pubkey: "71Prcc3Mwe5kag7yaG1wciPKDBxx1UivWRweHJoNkZxG"
[Enclave] SgxFile write key file success!
[+] enclave returned pubkey: "71Prcc3Mwe5kag7yaG1wciPKDBxx1UivWRweHJoNkZxG"
let enclave sign message: This message is true
[Enclave] restored sealed keyair with pubkey: "71Prcc3Mwe5kag7yaG1wciPKDBxx1UivWRweHJoNkZxG"
[+] enclave signature is correct!
[Enclave] Read 6198 bytes from Key file
[Enclave] len pubkey_slice: 8192
[Enclave] len keypair_json: 6198
[Enclave] Read 6198 bytes from Key file
[Enclave] decrypted data = This message is confidential

```