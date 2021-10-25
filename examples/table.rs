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
