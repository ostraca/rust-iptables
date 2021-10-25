# rust-iptables
A iptables bindings for Rust.

# Overview
Rust bindings for iptables, it provides a few major components:
* high-level handles, such as save/restore
* table/chain/rule support
* IPv4/IPv6 support

# Example
A basic chain/table example.

```toml
[dependencies]
rust-iptables = { version = "0.0.2" }
```

Then, on your main.rs:
```rust,no_run
use rust_iptables::iptables;

fn main() {
    let ipt = iptables::new().unwrap();

    assert!(ipt.new_chain("nat", "TESTINGCHAIN").is_ok());
    assert!(ipt.append("nat", "TESTINGCHAIN", "-j ACCEPT").is_ok());
    assert!(ipt.exists("nat", "TESTINGCHAIN", "-j ACCEPT").unwrap());
    assert!(ipt.delete("nat", "TESTINGCHAIN", "-j ACCEPT").is_ok());
    assert!(ipt.save_all("test").is_ok());
    assert!(ipt.restore_all("test").is_ok());
    assert!(ipt.delete_chain("nat", "TESTINGCHAIN").is_ok());

    assert!(ipt.change_policy("filter", "FORWARD", "ACCEPT").is_ok());
}
```

More examples can be found [here](https://github.com/ostraca/rust-iptables/tree/main/examples).

# Supported Rust Versions
This library is verified to work in rustc 1.51.0 (nightly), and the support of other versions needs more testing.

# License
This project is licensed under the [Apache License 2.0](https://github.com/ostraca/rust-iptables/blob/main/LICENSE).
