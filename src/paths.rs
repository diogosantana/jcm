use anyhow::{Result, bail};

pub fn resolve_keystore_alias(alias: &str, prefix: &str) -> String {
    if alias.starts_with(prefix) {
        alias.to_string()
    } else {
        format!("{prefix}{alias}")
    }
}

pub fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty()
        || !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid alias: {alias}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_keystore_alias_adds_prefix() {
        assert_eq!(resolve_keystore_alias("api", "jcm-"), "jcm-api");
        assert_eq!(resolve_keystore_alias("jcm-api", "jcm-"), "jcm-api");
    }
}
