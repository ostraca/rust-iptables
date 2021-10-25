use lazy_static::lazy_static;
use nix::fcntl::{flock, FlockArg};
use regex::{Match, Regex};
use std::convert::From;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::process::{Command, Output};
use std::vec::Vec;

lazy_static! {
    static ref RULE_SPLIT: Regex = Regex::new(r#"["'].+?["']|[^ ]+"#).unwrap();
}

trait SplitQuoted {
    fn split_quoted(&self) -> Vec<&str>;
}

impl SplitQuoted for str {
    fn split_quoted(&self) -> Vec<&str> {
        RULE_SPLIT
            .find_iter(self)
            .map(|m| Match::as_str(&m))
            .map(|s| s.trim_matches(|c| c == '"' || c == '\''))
            .collect::<Vec<_>>()
    }
}

fn error_from_str(msg: &str) -> Box<dyn Error> {
    msg.into()
}

fn output_to_result(output: Output) -> Result<(), Box<dyn Error>> {
    if !output.status.success() {
        return Err(Box::new(IptablesError::from(output)));
    }
    Ok(())
}

#[derive(Debug)]
pub struct IptablesError {
    pub code: i32,
    pub msg: String,
}

impl fmt::Display for IptablesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, msg: {}", self.code, self.msg)
    }
}

impl From<Output> for IptablesError {
    fn from(output: Output) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            msg: String::from_utf8_lossy(output.stderr.as_slice()).into(),
        }
    }
}

impl Error for IptablesError {}

pub struct IPTables {
    pub cmd: &'static str,
    pub save_cmd: &'static str,
    pub restore_cmd: &'static str,
    pub has_check: bool,
    pub has_wait: bool,

    pub v_major: isize,
    pub v_minor: isize,
    pub v_patch: isize,
}

#[cfg(target_os = "linux")]
pub fn new_with_protocol(is_ipv6: bool) -> Result<IPTables, Box<dyn Error>> {
    let cmd = if is_ipv6 { "ip6tables" } else { "iptables" };
    let save_cmd = if is_ipv6 {
        "ip6tables-save"
    } else {
        "iptables-save"
    };
    let restore_cmd = if is_ipv6 {
        "ip6tables-restore"
    } else {
        "iptables-restore"
    };

    let version_output = Command::new(cmd).arg("--version").output()?;
    let re = Regex::new(r"v(\d+)\.(\d+)\.(\d+)")?;
    let version_string = String::from_utf8_lossy(version_output.stdout.as_slice());
    let versions = re
        .captures(&version_string)
        .ok_or("invalid version number")?;
    let v_major = versions
        .get(1)
        .ok_or("unable to get major version number")?
        .as_str()
        .parse::<i32>()?;
    let v_minor = versions
        .get(2)
        .ok_or("unable to get minor version number")?
        .as_str()
        .parse::<i32>()?;
    let v_patch = versions
        .get(3)
        .ok_or("unable to get patch version number")?
        .as_str()
        .parse::<i32>()?;

    Ok(IPTables {
        cmd,
        save_cmd,
        restore_cmd,
        has_check: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 10),
        has_wait: (v_major > 1)
            || (v_major == 1 && v_minor > 4)
            || (v_major == 1 && v_minor == 4 && v_patch > 19),
        v_major: v_major as isize,
        v_minor: v_minor as isize,
        v_patch: v_patch as isize,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn new() -> Result<IPTables, Box<dyn Error>> {
    Err(error_from_str("iptables only works on Linux"))
}

#[cfg(target_os = "linux")]
pub fn new() -> Result<IPTables, Box<dyn Error>> {
    new_with_protocol(false)
}

impl IPTables {
    pub fn save_table(&self, table: &str, target: &str) -> Result<Output, Box<dyn Error>> {
        let cmd = format!("{} -t {} > {}", self.save_cmd, table, target);
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        Ok(output)
    }

    pub fn save_all(&self, target: &str) -> Result<Output, Box<dyn Error>> {
        let cmd = format!("{} > {}", self.save_cmd, target);
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        Ok(output)
    }

    pub fn restore_table(&self, table: &str, target: &str) -> Result<Output, Box<dyn Error>> {
        let cmd = format!("{} -t {} < {}", self.restore_cmd, table, target);
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        Ok(output)
    }

    pub fn restore_all(&self, target: &str) -> Result<Output, Box<dyn Error>> {
        let cmd = format!("{} < {}", self.restore_cmd, target);
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        Ok(output)
    }

    fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Output, Box<dyn Error>> {
        let mut file_lock = None;

        let mut output_cmd = Command::new(self.cmd);
        let output;

        if self.has_wait {
            output = output_cmd.args(args).arg("--wait").output()?;
        } else {
            file_lock = Some(File::create("/var/run/xtables_old.lock")?);

            let mut need_retry = true;
            let mut limit = 10;
            while need_retry {
                match flock(
                    file_lock.as_ref().unwrap().as_raw_fd(),
                    FlockArg::LockExclusiveNonblock,
                ) {
                    Ok(_) => need_retry = false,
                    Err(nix::Error::Sys(en)) if en == nix::errno::Errno::EAGAIN => {
                        if limit > 0 {
                            need_retry = true;
                            limit -= 1;
                        } else {
                            return Err(error_from_str("get lock failed"));
                        }
                    }
                    Err(e) => {
                        return Err(Box::new(e));
                    }
                }
            }
            output = output_cmd.args(args).output()?;
        }

        if let Some(f) = file_lock {
            drop(f)
        }
        Ok(output)
    }

    fn exists_old_version(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<bool, Box<dyn Error>> {
        self.run(&["-t", table, "-S"]).map(|output| {
            String::from_utf8_lossy(&output.stdout).contains(&format!("-A {} {}", chain, rule))
        })
    }

    fn get_list<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Vec<String>, Box<dyn Error>> {
        let stdout = self.run(args)?.stdout;
        Ok(String::from_utf8_lossy(stdout.as_slice())
            .trim()
            .split('\n')
            .map(String::from)
            .collect())
    }
}

impl IPTables {
    #[cfg(target_os = "linux")]
    pub fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool, Box<dyn Error>> {
        if !self.has_check {
            return self.exists_old_version(table, chain, rule);
        }

        self.run(&[&["-t", table, "-C", chain], rule.split_quoted().as_slice()].concat())
            .map(|output| output.status.success())
    }

    pub fn insert(
        &self,
        table: &str,
        chain: &str,
        position: i32,
        rule: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.run(
            &[
                &["-t", table, "-I", chain, &position.to_string()],
                rule.split_quoted().as_slice(),
            ]
            .concat(),
        )
        .and_then(output_to_result)
    }

    pub fn append(&self, table: &str, chain: &str, rule: &str) -> Result<(), Box<dyn Error>> {
        self.run(&[&["-t", table, "-A", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    pub fn append_unique(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<(), Box<dyn Error>> {
        if self.exists(table, chain, rule)? {
            return Err(error_from_str("the rule exists in the table/chain"));
        }

        self.append(table, chain, rule)
    }

    pub fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<(), Box<dyn Error>> {
        self.run(&[&["-t", table, "-D", chain], rule.split_quoted().as_slice()].concat())
            .and_then(output_to_result)
    }

    pub fn delete_if_exsits(
        &self,
        table: &str,
        chain: &str,
        rule: &str,
    ) -> Result<(), Box<dyn Error>> {
        while self.exists(table, chain, rule)? {
            self.delete(table, chain, rule)?;
        }

        Ok(())
    }

    pub fn list(&self, table: &str, chain: &str) -> Result<Vec<String>, Box<dyn Error>> {
        self.get_list(&["-t", table, "-S", chain])
    }

    pub fn list_with_counters(
        &self,
        table: &str,
        chain: &str,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        self.get_list(&["-t", table, "-v", "-S", chain])
    }

    pub fn list_chains(&self, table: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let mut list = Vec::new();
        let stdout = self.run(&["-t", table, "-S"])?.stdout;
        let output = String::from_utf8_lossy(stdout.as_slice());
        for item in output.trim().split('\n') {
            let fields = item.split(' ').collect::<Vec<&str>>();
            if fields.len() > 1 && (fields[0] == "-P" || fields[0] == "-N") {
                list.push(fields[1].to_string());
            }
        }
        Ok(list)
    }

    pub fn chain_exists(&self, table: &str, chain: &str) -> Result<bool, Box<dyn Error>> {
        self.run(&["-t", table, "-L", chain])
            .map(|output| output.status.success())
    }

    pub fn new_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-N", chain])
            .and_then(output_to_result)
    }

    pub fn flush_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-F", chain])
            .and_then(output_to_result)
    }

    pub fn rename_chain(
        &self,
        table: &str,
        old_chain: &str,
        new_chain: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-E", old_chain, new_chain])
            .and_then(output_to_result)
    }

    pub fn delete_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-X", chain])
            .and_then(output_to_result)
    }

    pub fn flush_and_delete_chain(&self, table: &str, chain: &str) -> Result<(), Box<dyn Error>> {
        while self.chain_exists(table, chain)? {
            match self.flush_chain(table, chain) {
                Ok(_) => {
                    return self.delete_chain(table, chain);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub fn flush_table(&self, table: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-F"]).and_then(output_to_result)
    }

    pub fn delete_table(&self, table: &str) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-X"]).and_then(output_to_result)
    }

    pub fn flush_all(&self) -> Result<(), Box<dyn Error>> {
        self.run(&["-F"]).and_then(output_to_result)
    }

    pub fn delete_all(&self) -> Result<(), Box<dyn Error>> {
        self.run(&["-X"]).and_then(output_to_result)
    }

    pub fn change_policy(
        &self,
        table: &str,
        chain: &str,
        target: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.run(&["-t", table, "-P", chain, target])
            .and_then(output_to_result)
    }

    pub fn get_iptables_version(self) -> (isize, isize, isize) {
        (self.v_major, self.v_minor, self.v_patch)
    }
}
