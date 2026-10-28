//! The `serde` feature: deserialising `PartialConfig` with unknown keys
//! collected (spec C6), `Config` deserialised strictly (C15) and
//! serialised for check mode in a fixed order (O8).

use std::collections::BTreeMap;

use serde::de::{Error as _, IgnoredAny};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::partial::UnknownKeys;
use super::{Config, PartialConfig};

/// Flattened into each table, it receives the keys no field takes.
impl<'de> Deserialize<'de> for UnknownKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keys = BTreeMap::<String, IgnoredAny>::deserialize(deserializer)?;
        Ok(UnknownKeys(keys.into_keys().collect()))
    }
}

/// Never written: flattened, an empty map adds no key.
impl Serialize for UnknownKeys {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BTreeMap::<String, String>::new().serialize(serializer)
    }
}

/// The strict conversion of C15.
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Config::try_from(PartialConfig::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// The rendering of O8: tables `host`, `resolvers`, `tunnels`, `sessions`,
/// entries in byte order of their names, keys in the order of the field
/// tables of the specification, defaults that were not configured absent
/// (a format without `null`, as TOML, omits them).
impl Serialize for Config {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PartialConfig::from(self).serialize(serializer)
    }
}
