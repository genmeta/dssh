use std::borrow::Cow;

use snafu::OptionExt;

use crate::error::{ExpandError, ExpandSnafu};

pub fn expand_path(path: &str) -> Result<Cow<'_, str>, ExpandError> {
    if path.contains('~') {
        let home = dirs::home_dir()
            .context(ExpandSnafu { chars: "~" })?
            .display()
            .to_string();
        return Ok(path.replace('~', &home).into());
    }
    Ok(Cow::Borrowed(path))
}
