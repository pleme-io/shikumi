//! Secret resolution for config fields that reference external commands.
//!
//! Desktop and server apps often need to pull secrets from password managers,
//! vaults, or keychain CLIs without ever writing the secret value to disk.
//! The `*_command` convention lets a config author point at a shell command
//! whose stdout *is* the secret:
//!
//! ```yaml
//! # hanabi.yaml
//! jwt_secret_command: "op read 'op://prod/hanabi/jwt-secret'"
//! api_key_command: "akeyless get-secret-value --name /prod/api_key"
//! ```
//!
//! At startup the app calls [`resolve_command`] on each `*_command` field and
//! uses the trimmed stdout as the effective secret. Errors bubble up as
//! [`ShikumiError`] so the app can fail fast with a clear reason.
//!
//! # Example
//!
//! ```no_run
//! use shikumi::secret;
//!
//! let jwt_secret = secret::resolve_command("echo hunter2")?;
//! assert_eq!(jwt_secret, "hunter2");
//! # Ok::<_, shikumi::ShikumiError>(())
//! ```

use std::process::Command;

use crate::error::ShikumiError;

/// Run a shell command and return its trimmed stdout as a secret value.
///
/// Executes through `sh -c` so consumers can use shell features (pipes,
/// redirects, env-var expansion). Non-zero exit status is reported as a
/// [`ShikumiError::Parse`] with the stderr payload included so the operator
/// can diagnose a vault-lookup failure. Stdout is trimmed of trailing
/// whitespace — `op read` and `akeyless get-secret-value` both append a
/// newline that would otherwise corrupt the secret.
///
/// # Errors
///
/// - [`ShikumiError::Io`] if the shell itself cannot be spawned.
/// - [`ShikumiError::Parse`] if the command exits with a non-zero status or
///   its stdout is not valid UTF-8.
pub fn resolve_command(cmd: &str) -> Result<String, ShikumiError> {
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ShikumiError::Parse(format!(
            "secret command {cmd:?} exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| ShikumiError::Parse(format!("secret command stdout not utf-8: {e}")))?;
    Ok(stdout.trim_end().to_owned())
}

/// Resolve a secret from either a plaintext value or a `*_command` reference.
///
/// Apps typically expose two config fields for each secret — a literal
/// `jwt_secret: Option<String>` and a `jwt_secret_command: Option<String>` —
/// and pick whichever is set. This helper encodes that precedence in one
/// place: if `literal` is present, return it; otherwise resolve `command`
/// via [`resolve_command`]. Errors when neither is set.
///
/// # Errors
///
/// - [`ShikumiError::Parse`] if both fields are `None` (fails with
///   `missing_field_name` for a useful diagnostic) or if
///   [`resolve_command`] fails.
pub fn resolve_or_command(
    literal: Option<&str>,
    command: Option<&str>,
    missing_field_name: &str,
) -> Result<String, ShikumiError> {
    if let Some(value) = literal {
        return Ok(value.to_owned());
    }
    if let Some(cmd) = command {
        return resolve_command(cmd);
    }
    Err(ShikumiError::Parse(format!(
        "secret {missing_field_name} not provided (set {missing_field_name} or {missing_field_name}_command)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_echo_returns_stdout() {
        let value = resolve_command("echo hunter2").unwrap();
        assert_eq!(value, "hunter2");
    }

    #[test]
    fn resolve_trims_trailing_newline() {
        // `echo` always appends \n — make sure it gets stripped.
        let value = resolve_command("printf 'secret\\n'").unwrap();
        assert_eq!(value, "secret");
    }

    #[test]
    fn resolve_preserves_leading_whitespace() {
        // Leading whitespace is meaningful (base64/JWT payload may start with it);
        // we only trim trailing newlines.
        let value = resolve_command("printf '  hello'").unwrap();
        assert_eq!(value, "  hello");
    }

    #[test]
    fn resolve_multiline_stdout() {
        // Commands like `gpg --decrypt` may produce multi-line secrets. Keep
        // internal newlines; only trim trailing ones.
        let value = resolve_command("printf 'line1\\nline2\\n'").unwrap();
        assert_eq!(value, "line1\nline2");
    }

    #[test]
    fn resolve_command_failure_surfaces_stderr() {
        let err = resolve_command("echo oops >&2; exit 17").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("oops"), "stderr should appear in error: {msg}");
        assert!(msg.contains("17") || msg.contains("exit"), "exit status in error: {msg}");
    }

    #[test]
    fn resolve_command_failure_is_parse_variant() {
        let err = resolve_command("exit 1").unwrap_err();
        assert!(err.is_parse(), "failed command should map to Parse variant");
    }

    #[test]
    fn resolve_nonexistent_command_fails() {
        // `sh -c` returns a non-zero exit when the inner command is missing,
        // rather than an IO error — verify we surface that cleanly.
        let err = resolve_command("nonexistent-command-zzz-xyzzy").unwrap_err();
        assert!(err.is_parse());
    }

    #[test]
    fn resolve_empty_command_succeeds_empty_stdout() {
        let value = resolve_command(":").unwrap();
        assert_eq!(value, "");
    }

    #[test]
    fn resolve_or_command_prefers_literal() {
        let value = resolve_or_command(Some("plain"), Some("echo ignored"), "jwt_secret").unwrap();
        assert_eq!(value, "plain");
    }

    #[test]
    fn resolve_or_command_falls_back_to_command() {
        let value = resolve_or_command(None, Some("echo from-cmd"), "jwt_secret").unwrap();
        assert_eq!(value, "from-cmd");
    }

    #[test]
    fn resolve_or_command_errors_when_neither_set() {
        let err = resolve_or_command(None, None, "jwt_secret").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("jwt_secret"), "error should name the missing field");
        assert!(msg.contains("jwt_secret_command"), "error should suggest the _command fallback");
    }

    #[test]
    fn resolve_or_command_propagates_command_error() {
        let err = resolve_or_command(None, Some("exit 1"), "api_key").unwrap_err();
        assert!(err.is_parse());
    }

    #[test]
    fn resolve_command_with_shell_features() {
        // Confirms we execute through `sh -c` (pipelines must work).
        let value = resolve_command("echo abc | tr a-z A-Z").unwrap();
        assert_eq!(value, "ABC");
    }
}
