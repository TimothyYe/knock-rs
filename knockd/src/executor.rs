use anyhow::{bail, Result};
use std::process::Command;

pub fn execute_command(command: &str) -> Result<()> {
    let mut parts = command.split_whitespace();
    let Some(program) = parts.next() else {
        bail!("cannot execute an empty command");
    };

    Command::new(program).args(parts).spawn()?.wait()?;

    Ok(())
}

mod tests {
    #[test]
    fn test_execute_command() {
        let result = crate::executor::execute_command("ls -lh ./");
        assert!(result.is_ok());
    }
}
