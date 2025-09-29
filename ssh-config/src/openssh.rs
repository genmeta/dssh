use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use either::Either::{self, Left, Right};
use http::Uri;
use peg::str::LineCol;
use snafu::{IntoError, OptionExt, ResultExt};
use tokio::fs;

use crate::{
    ast::{ConfigFile, ConfigMap, IStr, PositionedToken},
    error::*,
    parse::{single_int_parser, single_str_parser, single_uri_parser},
    pattern::SinglePattern,
};

const CANNOT_READ_USER_CONFIG: &str = "Cannot locate home directory to locate user's openssh configuration file (usually ~/.ssh/config)";
pub fn user_config_file_path() -> Option<PathBuf> {
    dirs::home_dir().map(|mut path| {
        path.push(".ssh");
        path.push("config");
        path
    })
}

const CANNOT_READ_SYSTEM_CONFIG: &str =
    "Cannot locate system-wide openssh configuration file (usually /etc/ssh/ssh_config)";
pub fn system_config_file_path() -> Option<PathBuf> {
    #[cfg(unix)]
    return Some(PathBuf::from("/etc/ssh/ssh_config"));
    #[cfg(not(unix))]
    return None;
}

/// https://man7.org/linux/man-pages/man5/ssh_config.5.html
pub mod keywords {
    use super::*;

    pub const HOST: IStr<&str> = IStr::new("Host");
    pub const MATCH: IStr<&str> = IStr::new("Match");
    pub const MATCHERS: &[IStr<&str>] = &[HOST, MATCH];

    pub const USER: IStr<&str> = IStr::new("User");
    pub const HOSTNAME: IStr<&str> = IStr::new("Hostname");
    pub const ID: IStr<&str> = IStr::new("Id");
    pub const CONNECT_TIMEOUT: IStr<&str> = IStr::new("ConnectTimeout");
}

#[derive(Debug, Clone)]
pub struct Config {
    pub user: Option<String>,
    pub hostname: Option<Uri>,
    // should be ClinetName(not expended here)
    pub id: Option<String>,
    pub connect_timeout: Option<Duration>,
}

fn try_take_and_parse_with<'c, P, T>(
    host: &str,
    map: &ConfigMap<'c, 'c>,
    keyword: IStr<&'static str>,
    new_parser: impl FnOnce(IStr<&'static str>) -> P,
) -> Result<Option<T>, ParseConfigError>
where
    P: FnOnce(
        &str,
        Option<&(LineCol, Vec<PositionedToken<&'c str>>)>,
    ) -> Result<T, ParseConfigError>,
    T: 'c,
{
    map.get(&keyword)
        .map(|pair| new_parser(keyword)(host, Some(pair)))
        .transpose()
}

pub fn parse_config_to_map<'c>(
    host: &str,
    config: Either<&Path, &str>,
    content: &'c str,
) -> Result<ConfigMap<'c, 'c>, ReadConfigError> {
    match ConfigFile::new(content).map_err(ParseConfigError::from) {
        Ok(config) => Ok(config.query(keywords::MATCHERS, host, |host| {
            SinglePattern::new(host.to_string())
        })),
        Err(error) => Err(match config {
            Either::Left(path) => ParseConfigFileSnafu { path }.into_error(error),
            Either::Right(content) => ParseConfigContentSnafu { content }.into_error(error),
        }),
    }
}

pub fn parse_config_maps<'a, Key: Clone>(
    host: &str,
    maps: impl IntoIterator<Item = (Key, &'a ConfigMap<'a, 'a>)>,
) -> Result<Config, (Key, ParseConfigError)> {
    let mut user = None;
    let mut hostname = None;
    let mut id = None;
    let mut connect_timeout = None;

    for (key, map) in maps {
        if user.is_none() {
            user = try_take_and_parse_with(host, map, keywords::USER, single_str_parser)
                .map_err(|e| (key.clone(), e))?
                .map(|s| s.to_string());
        }
        if hostname.is_none() {
            hostname = try_take_and_parse_with(host, map, keywords::HOSTNAME, single_uri_parser)
                .map_err(|e| (key.clone(), e))?;
        }
        if id.is_none() {
            id = try_take_and_parse_with(host, map, keywords::ID, single_str_parser)
                .map_err(|e| (key.clone(), e))?
                .map(|s| s.parse().unwrap());
        }
        if connect_timeout.is_none() {
            connect_timeout =
                try_take_and_parse_with(host, map, keywords::CONNECT_TIMEOUT, single_int_parser)
                    .map_err(|e| (key.clone(), e))?
                    .map(Duration::from_secs);
        }
    }

    Ok(Config {
        user,
        hostname,
        id,
        connect_timeout,
    })
}

pub async fn read_config(
    cli_options: &[String],
    host: &str,
) -> Result<(Config, Vec<(&'static str, ReadConfigError)>), ReadConfigError> {
    let mut config_maps = cli_options.iter().try_fold(vec![], |mut maps, content| {
        let map = parse_config_to_map(host, Right(content), content)?;
        maps.push((Right(content.as_str()), map));
        Ok(maps)
    })?;

    let mut file_contents = vec![];
    let mut errors = Vec::new();

    let read_user_config_file = async {
        let path = user_config_file_path().context(LocateConfigFileSnafu {
            message: CANNOT_READ_USER_CONFIG,
        })?;
        let content = fs::read_to_string(&path)
            .await
            .context(ReadConfigFileSnafu { path: &path })?;
        Ok((path, content))
    };

    let read_system_config = async {
        let path = system_config_file_path().context(LocateConfigFileSnafu {
            message: CANNOT_READ_SYSTEM_CONFIG,
        })?;
        let content = fs::read_to_string(&path)
            .await
            .context(ReadConfigFileSnafu { path: &path })?;
        Ok((path, content))
    };

    match read_user_config_file.await {
        Ok(pair) => file_contents.push(pair),
        Err(error) => errors.push(("Cannot read user ssh configuration", error)),
    }
    match read_system_config.await {
        Ok(pair) => file_contents.push(pair),
        Err(error) => errors.push(("Cannot read system ssh configuration", error)),
    }

    config_maps.extend(
        file_contents
            .iter()
            .try_fold(vec![], |mut maps, (path, content)| {
                maps.push((Left(path), parse_config_to_map(host, Left(path), content)?));
                Ok(maps)
            })?,
    );

    let host = parse_config_maps(host, config_maps.iter().map(|(key, m)| (key, m))).map_err(
        |(key, e)| match *key {
            Either::Left(path) => ParseConfigFileSnafu { path }.into_error(e),
            Either::Right(content) => ParseConfigContentSnafu { content }.into_error(e),
        },
    )?;
    Ok((host, errors))
}
