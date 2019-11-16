## Two party EdDSA signature scheme

TODO:

* Proposal

Problems:

* Men in the middle attack, replay msg
* Men in the middle attack, cannot generate valid signature

### How to:

Build:

```
cargo build --release
```

Start server:

```
./target/release/server
```

Generate keypair:

```
➜  two-party-eddsa git:(tcp) ./target/release/client -g
aggregated_pubkey: "1b3342159aac8ce36ffc2f5a6a3d50697af013e05d81fb7d7ca35f82cdd2dd76"
elapsed_time: 3 ms
```

Sign a message:

```
➜  two-party-eddsa git:(tcp) ✗ ./target/release/client -s -m "hello world"
R: "55937d251295d1f06e8cbcf349ef414ea60d998f0f7368439349baaeb4d4782e"
s: "5d6384608d5bff32531a5cae1e7473660c0ccbf8e254fe9d40eb0e07e193f408"
elapsed_time: 5 ms
```

Verify the signature:

```
➜  two-party-eddsa git:(tcp) ✗ ./target/release/client -v -m "hello world" --sig-r 55937d251295d1f06e8cbcf349ef414ea60d998f0f7368439349baaeb4d4782e --sig-s 5d6384608d5bff32531a5cae1e7473660c0ccbf8e254fe9d40eb0e07e193f408 --pubkey 1b3342159aac8ce36ffc2f5a6a3d50697af013e05d81fb7d7ca35f82cdd2dd76
true
elapsed_time: 1 ms
```



