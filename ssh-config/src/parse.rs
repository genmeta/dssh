use std::ops::Deref;

use peg::str::LineCol;
use snafu::ResultExt;
use tokio::fs;

use crate::{
    ast::{IStr, PositionedToken},
    error::{
        ExpandAssetPathSnafu, MissingParameterSnafu, ParseConfigError, ReadAssetFileSnafu,
        TooManyArgumentsSnafu,
    },
    path::expand_path,
};

pub fn take_single_str<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    pattern: &str,
    keyword: IStr<&'static str>,
    arguments: Option<&(LineCol, A)>,
) -> Result<(LineCol, &'c str), ParseConfigError> {
    match arguments.map(|(loc, args)| (loc, args.as_ref())) {
        Some((&location, [argument])) => Ok((location, argument.deref())),
        Some((&loc, ..)) => TooManyArgumentsSnafu { location: loc }.fail(),
        None => MissingParameterSnafu { pattern, keyword }.fail(),
    }
}

pub fn single_str_parser<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    keyword: IStr<&'static str>,
) -> impl Fn(&str, Option<&(LineCol, A)>) -> Result<&'c str, ParseConfigError> {
    move |pattern, arguments| take_single_str(pattern, keyword, arguments).map(|(_, arg)| arg)
}

#[allow(clippy::type_complexity)]
pub fn single_path_parser<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    keyword: IStr<&'static str>,
) -> impl AsyncFn(&str, Option<&(LineCol, A)>) -> Result<(String, Vec<u8>), ParseConfigError> {
    async move |pattern, arguments| {
        let (location, path) = take_single_str(pattern, keyword, arguments)?;
        let path = expand_path(path).context(ExpandAssetPathSnafu { location })?;
        let data = fs::read(path.deref()).await.context(ReadAssetFileSnafu {
            location,
            path: path.deref(),
        })?;
        Ok((path.to_string(), data))
    }
}

#[cfg(feature = "openssh")]
pub fn single_int_parser<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    keyword: IStr<&'static str>,
) -> impl Fn(&str, Option<&(LineCol, A)>) -> Result<u64, ParseConfigError> {
    use crate::error::ParseIntegerSnafu;
    move |pattern, arguments| {
        let (location, argument) = take_single_str(pattern, keyword, arguments)?;
        argument.parse().context(ParseIntegerSnafu { location })
    }
}

#[cfg(feature = "openssh")]
pub fn single_uri_parser<'c, A: AsRef<[PositionedToken<&'c str>]>>(
    keyword: IStr<&'static str>,
) -> impl Fn(&str, Option<&(LineCol, A)>) -> Result<http::Uri, ParseConfigError> {
    use crate::error::ParseUriSnafu;
    move |pattern, arguments| {
        let (location, argument) = take_single_str(pattern, keyword, arguments)?;
        argument.parse().context(ParseUriSnafu { location })
    }
}
