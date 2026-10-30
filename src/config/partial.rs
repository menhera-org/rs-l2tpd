//! `PartialConfig`: merged but unvalidated documents, and the strict and
//! lenient conversions with their problems (spec C2, C5, C6, C10, C12, C15).

use std::collections::BTreeMap;
use std::fmt;
use std::mem;
use std::path::{Path, PathBuf};

use super::{
    Config, Dhcpv6Identity, Entry, HostConfig, L2tpIfName, Mistake, ResolverConfig, SessionConfig,
    TunnelConfig, text,
};
use crate::Error;

/// The keys of a table that no rule names (C6), collected by the `serde`
/// feature.
#[derive(Clone, Default)]
pub(crate) struct UnknownKeys(pub(crate) Vec<String>);

#[derive(Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(default)
)]
pub(crate) struct PartialHost {
    pub(crate) fix_bindv6only: Option<bool>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(crate) unknown: UnknownKeys,
}

impl PartialHost {
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    fn is_empty(&self) -> bool {
        self.fix_bindv6only.is_none()
    }
}

// Field order is the order of C16, which the rendering keeps (O8).
#[derive(Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(default)
)]
pub(crate) struct PartialResolver {
    pub(crate) addresses: Option<Vec<String>>,
    pub(crate) method: Option<String>,
    pub(crate) bind_interface: Option<String>,
    pub(crate) dhcpv6_identity: Option<String>,
    pub(crate) dhcpv6_duid: Option<String>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(crate) unknown: UnknownKeys,
}

// Integers stay `i64`, TOML's own, so that an identifier out of range is
// a mistake of the entry, not of the document (C6, C10).
#[derive(Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(default)
)]
pub(crate) struct PartialTunnel {
    pub(crate) tunnel_id: Option<i64>,
    pub(crate) peer_tunnel_id: Option<i64>,
    pub(crate) remote_addr: Option<String>,
    pub(crate) ip_version: Option<String>,
    pub(crate) bind_interface: Option<String>,
    pub(crate) resolver_name: Option<String>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(crate) unknown: UnknownKeys,
}

#[derive(Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(default)
)]
pub(crate) struct PartialSession {
    pub(crate) tunnel_name: Option<String>,
    pub(crate) session_id: Option<i64>,
    pub(crate) peer_session_id: Option<i64>,
    pub(crate) interface_name: Option<String>,
    pub(crate) interface_hwaddr: Option<String>,
    pub(crate) cookie: Option<String>,
    pub(crate) peer_cookie: Option<String>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(crate) unknown: UnknownKeys,
}

/// The configuration as documents give it: merged, every field optional,
/// textual values still text, unknown keys remembered (C5, C6).
///
/// With the `serde` feature it deserialises from any format; documents
/// are merged with [`merge`](Self::merge) and converted with
/// [`into_config_lenient`](Self::into_config_lenient) at start-up,
/// [`into_config_with_previous`](Self::into_config_with_previous) on a
/// reload, or strictly with `Config::try_from`. It has no `Debug`, because
/// it holds cookies as text (O5).
#[derive(Clone, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(default)
)]
pub struct PartialConfig {
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "PartialHost::is_empty")
    )]
    pub(crate) host: PartialHost,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "BTreeMap::is_empty"))]
    pub(crate) resolvers: BTreeMap<String, PartialResolver>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "BTreeMap::is_empty"))]
    pub(crate) tunnels: BTreeMap<String, PartialTunnel>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "BTreeMap::is_empty"))]
    pub(crate) sessions: BTreeMap<String, PartialSession>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub(crate) unknown: UnknownKeys,
    /// Unknown keys moved out of the tables, with their documents.
    #[cfg_attr(feature = "serde", serde(skip))]
    labeled: Vec<(Option<PathBuf>, Vec<String>)>,
}

macro_rules! replace_given {
    ($into:expr, $from:expr, $($field:ident),+) => {
        $(if $from.$field.is_some() {
            $into.$field = $from.$field;
        })+
    };
}

impl PartialConfig {
    /// The empty document.
    pub fn new() -> Self {
        PartialConfig::default()
    }

    /// Names `source`, the file this document was read from, in the
    /// problems of its unknown keys (C6, C15). Call it before merging.
    pub fn set_source(&mut self, source: impl AsRef<Path>) {
        self.label(Some(source.as_ref()));
    }

    /// Merges a later document into this one (C2): a value of `later`
    /// replaces the same key's, keys it does not mention are kept, tables
    /// are merged.
    pub fn merge(&mut self, mut later: PartialConfig) {
        self.label(None);
        later.label(None);
        self.labeled.append(&mut later.labeled);
        replace_given!(self.host, later.host, fix_bindv6only);
        for (name, from) in later.resolvers {
            let into = self.resolvers.entry(name).or_default();
            replace_given!(
                into,
                from,
                addresses,
                method,
                bind_interface,
                dhcpv6_identity,
                dhcpv6_duid
            );
        }
        for (name, from) in later.tunnels {
            let into = self.tunnels.entry(name).or_default();
            replace_given!(
                into,
                from,
                tunnel_id,
                peer_tunnel_id,
                remote_addr,
                ip_version,
                bind_interface,
                resolver_name
            );
        }
        for (name, from) in later.sessions {
            let into = self.sessions.entry(name).or_default();
            replace_given!(
                into,
                from,
                tunnel_name,
                session_id,
                peer_session_id,
                interface_name,
                interface_hwaddr,
                cookie,
                peer_cookie
            );
        }
    }

    /// The start-up conversion (C10): every entry valid, corrected or left
    /// out, with every problem. The result may be empty.
    pub fn into_config_lenient(self) -> (Config, Vec<Problem>) {
        let (config, problems, _) = self.convert(None);
        (config, problems)
    }

    /// The reload conversion against the accepted configuration (C12): an
    /// entry with a hard mistake that `previous` has under the same name
    /// keeps its values. `Err` when the reload is refused as a whole,
    /// because such values no longer fit the new entries; the problem of
    /// effect [`Effect::Refused`] names the entry.
    pub fn into_config_with_previous(
        self,
        previous: &Config,
    ) -> std::result::Result<(Config, Vec<Problem>), Vec<Problem>> {
        match self.convert(Some(previous)) {
            (_, problems, true) => Err(problems),
            (config, problems, false) => Ok((config, problems)),
        }
    }

    /// Moves the unknown keys of the tables to `labeled`, with `source`.
    fn label(&mut self, source: Option<&Path>) {
        let mut paths = Vec::new();
        let mut take = |prefix: &[&str], keys: &mut UnknownKeys| {
            for key in mem::take(&mut keys.0) {
                let mut path: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
                path.push(key);
                paths.push((source.map(Path::to_path_buf), path));
            }
        };
        take(&[], &mut self.unknown);
        take(&["host"], &mut self.host.unknown);
        for (name, entry) in &mut self.resolvers {
            take(&["resolvers", name], &mut entry.unknown);
        }
        for (name, entry) in &mut self.tunnels {
            take(&["tunnels", name], &mut entry.unknown);
        }
        for (name, entry) in &mut self.sessions {
            take(&["sessions", name], &mut entry.unknown);
        }
        self.labeled.append(&mut paths);
    }

    /// Both conversions. Kinds go in dependency order, so that a session
    /// sees the tunnels that were kept; within a kind, the new valid
    /// entries in name order, then the retained ones (C12's two passes).
    /// The flag is a refusal, which `previous = None` never causes.
    fn convert(mut self, previous: Option<&Config>) -> (Config, Vec<Problem>, bool) {
        self.label(None);
        let mut problems: Vec<Problem> = self
            .labeled
            .into_iter()
            .map(|(source, path)| Problem {
                kind: ProblemKind::Document { source, path },
                effect: Effect::Ignored,
                message: "unknown key".into(),
            })
            .collect();
        let mut config = Config::new();
        config.host = HostConfig {
            fix_bindv6only: self.host.fix_bindv6only,
        };
        let refused = convert_kind(
            &mut config,
            &mut problems,
            previous,
            self.resolvers.into_iter().map(|(n, e)| (n, resolver(e))),
        ) || convert_kind(
            &mut config,
            &mut problems,
            previous,
            self.tunnels.into_iter().map(|(n, e)| (n, tunnel(e))),
        ) || convert_kind(
            &mut config,
            &mut problems,
            previous,
            self.sessions.into_iter().map(|(n, e)| (n, session(e))),
        );
        (config, problems, refused)
    }
}

type Parsed<E> = std::result::Result<(E, Vec<Mistake>), Mistake>;

/// Inserts the entries of one kind; `true` when a retained entry no longer
/// fits, which refuses the reload (C12).
fn convert_kind<E: Entry>(
    config: &mut Config,
    problems: &mut Vec<Problem>,
    previous: Option<&Config>,
    entries: impl Iterator<Item = (String, Parsed<E>)>,
) -> bool {
    let mut retained = Vec::new();
    for (name, parsed) in entries {
        let inserted = parsed
            .and_then(|(entry, tolerated)| config.insert(name.clone(), entry).map(|()| tolerated));
        match inserted {
            Ok(tolerated) => problems.extend(
                tolerated
                    .into_iter()
                    .map(|m| Problem::entry(E::KIND, &name, m, Effect::Corrected)),
            ),
            Err(mistake) => match previous.and_then(|p| E::table(p).get(&name)) {
                Some(old) => {
                    problems.push(Problem::entry(
                        E::KIND,
                        &name,
                        mistake,
                        Effect::KeptPrevious,
                    ));
                    retained.push((name, old.clone()));
                }
                None => problems.push(Problem::entry(E::KIND, &name, mistake, Effect::LeftOut)),
            },
        }
    }
    for (name, old) in retained {
        if let Err(mistake) = config.insert(name.clone(), old) {
            problems.push(Problem::entry(E::KIND, &name, mistake, Effect::Refused));
            return true;
        }
    }
    false
}

fn required<T>(value: Option<T>, field: &'static str) -> std::result::Result<T, Mistake> {
    value.ok_or_else(|| Mistake::hard(field, "required"))
}

/// An identifier: 1 to 2^32-1 (C7, C8).
fn id(value: Option<i64>, field: &'static str) -> std::result::Result<Option<u32>, Mistake> {
    value
        .map(|v| {
            u32::try_from(v)
                .ok()
                .filter(|v| *v != 0)
                .ok_or_else(|| Mistake::hard(field, format!("{v} is not in 1 to 4294967295")))
        })
        .transpose()
}

fn ifname(
    value: Option<String>,
    field: &'static str,
) -> std::result::Result<Option<L2tpIfName>, Mistake> {
    value
        .map(|name| text::ifname(name.as_bytes()).map_err(|e| Mistake::hard(field, e)))
        .transpose()
}

/// Corrects the tolerated mistakes `check` finds until none is left; a
/// hard one ends the entry (C10).
fn tolerate<E>(
    mut entry: E,
    mut tolerated: Vec<Mistake>,
    check: fn(&E) -> std::result::Result<(), Mistake>,
    correct: fn(&mut E, &Mistake),
) -> Parsed<E> {
    loop {
        match check(&entry) {
            Ok(()) => return Ok((entry, tolerated)),
            Err(mistake) if mistake.hard => return Err(mistake),
            Err(mistake) => {
                correct(&mut entry, &mistake);
                tolerated.push(mistake);
            }
        }
    }
}

fn tunnel(p: PartialTunnel) -> Parsed<TunnelConfig> {
    let mut tunnel = TunnelConfig {
        tunnel_id: required(id(p.tunnel_id, "tunnel_id")?, "tunnel_id")?,
        peer_tunnel_id: id(p.peer_tunnel_id, "peer_tunnel_id")?,
        remote_addr: None,
        ip_version: None,
        bind_interface: ifname(p.bind_interface, "bind_interface")?,
        resolver_name: p.resolver_name,
    };
    let mut tolerated = Vec::new();
    let mut hint = None;
    match p.remote_addr.as_deref().map(text::remote) {
        Some(Ok(addr)) => tunnel.remote_addr = Some(addr),
        Some(Err((message, family))) => {
            hint = family;
            tolerated.push(Mistake::tolerated("remote_addr", message));
        }
        None => tolerated.push(Mistake::tolerated("remote_addr", "required")),
    }
    match p.ip_version.as_deref().map(|v| text::family(v).ok_or(v)) {
        Some(Ok(family)) => tunnel.ip_version = Some(family),
        Some(Err(v)) => tolerated.push(Mistake::tolerated(
            "ip_version",
            format!("{v:?} is not \"V4\" or \"V6\""),
        )),
        None => {}
    }
    if tunnel.remote_addr.is_some()
        && let Err(mistake) = tunnel.check()
        && mistake.hard
    {
        return Err(mistake);
    }
    if !tolerated.is_empty() {
        tunnel.make_peerless(hint);
    }
    if p.remote_addr
        .as_deref()
        .and_then(text::ip_literal)
        .is_some()
        && let Some(resolver) = tunnel.resolver_name.take()
    {
        tolerated.push(Mistake::tolerated(
            "resolver_name",
            format!("{resolver:?} is used only with a host name"),
        ));
    }
    tolerate(
        tunnel,
        tolerated,
        TunnelConfig::check,
        |tunnel, mistake| match mistake.field {
            Some("resolver_name") => tunnel.resolver_name = None,
            _ => tunnel.make_peerless(None),
        },
    )
}

fn session(p: PartialSession) -> Parsed<SessionConfig> {
    let cookie = |value: Option<String>, field| {
        value
            .map(|c| text::cookie(&c).map_err(|e| Mistake::hard(field, e)))
            .transpose()
    };
    let mut session = SessionConfig {
        tunnel_name: required(p.tunnel_name, "tunnel_name")?,
        session_id: required(id(p.session_id, "session_id")?, "session_id")?,
        peer_session_id: id(p.peer_session_id, "peer_session_id")?,
        interface_name: required(
            ifname(p.interface_name, "interface_name")?,
            "interface_name",
        )?,
        interface_hwaddr: None,
        cookie: cookie(p.cookie, "cookie")?,
        peer_cookie: cookie(p.peer_cookie, "peer_cookie")?,
    };
    session.check()?;
    let mut tolerated = Vec::new();
    match p.interface_hwaddr.as_deref().map(text::hwaddr) {
        Some(Ok(addr)) => session.interface_hwaddr = Some(addr),
        Some(Err(e)) => tolerated.push(Mistake::tolerated("interface_hwaddr", e)),
        None => {}
    }
    Ok((session, tolerated))
}

fn resolver(p: PartialResolver) -> Parsed<ResolverConfig> {
    let addresses = match p.addresses {
        Some(list) if list.is_empty() => return Err(Mistake::hard("addresses", "empty")),
        Some(list) => list
            .iter()
            .map(|a| text::name_server(a))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Mistake::hard("addresses", e))?,
        None => Vec::new(),
    };
    let method = p
        .method
        .as_deref()
        .map(text::method)
        .transpose()
        .map_err(|e| Mistake::hard("method", e))?;
    let dhcpv6_identity = match (p.dhcpv6_identity.as_deref(), p.dhcpv6_duid.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(Mistake::hard(
                "dhcpv6_duid",
                "dhcpv6_identity and dhcpv6_duid are exclusive",
            ));
        }
        (Some(t), None) => {
            Some(text::identity(t).map_err(|e| Mistake::hard("dhcpv6_identity", e))?)
        }
        (None, Some(t)) => Some(text::duid(t).map_err(|e| Mistake::hard("dhcpv6_duid", e))?),
        (None, None) => None,
    };
    let resolver = ResolverConfig {
        addresses,
        method,
        bind_interface: ifname(p.bind_interface, "bind_interface")?,
        dhcpv6_identity,
    };
    tolerate(
        resolver,
        Vec::new(),
        ResolverConfig::check,
        |resolver, _| resolver.dhcpv6_identity = None,
    )
}

impl TryFrom<PartialConfig> for Config {
    type Error = Error;

    /// The strict conversion (C15): fails on the first problem of any
    /// kind, an unknown key included, naming the entry or the key.
    fn try_from(partial: PartialConfig) -> std::result::Result<Self, Error> {
        let (config, problems, _) = partial.convert(None);
        match problems.first() {
            None => Ok(config),
            Some(problem) => Err(Error::InvalidConfig(problem.subject())),
        }
    }
}

/// The configuration as documents would give it, for rendering (O8):
/// tolerated mistakes corrected, defaults that were not configured absent.
/// Interface names that are not UTF-8 are rendered lossily, because the
/// documents are UTF-8 (A22).
impl From<&Config> for PartialConfig {
    fn from(config: &Config) -> Self {
        let name = |n: &L2tpIfName| n.to_string_lossy().into_owned();
        let resolvers = config.resolvers.iter().map(|(n, r)| {
            let entry = PartialResolver {
                addresses: (!r.addresses.is_empty())
                    .then(|| r.addresses.iter().map(ToString::to_string).collect()),
                method: r.method.map(|m| m.to_string()),
                bind_interface: r.bind_interface.as_ref().map(name),
                dhcpv6_identity: match &r.dhcpv6_identity {
                    Some(Dhcpv6Identity::LinkLayer) => Some("link-layer".into()),
                    Some(Dhcpv6Identity::Anonymous) => Some("anonymous".into()),
                    Some(Dhcpv6Identity::Random) => Some("random".into()),
                    _ => None,
                },
                dhcpv6_duid: match &r.dhcpv6_identity {
                    Some(Dhcpv6Identity::Duid(duid)) => Some(text::to_hex(duid)),
                    _ => None,
                },
                unknown: UnknownKeys::default(),
            };
            (n.clone(), entry)
        });
        let tunnels = config.tunnels.iter().map(|(n, t)| {
            let entry = PartialTunnel {
                tunnel_id: Some(t.tunnel_id.into()),
                peer_tunnel_id: t.peer_tunnel_id.map(Into::into),
                remote_addr: t.remote_addr.as_ref().map(ToString::to_string),
                ip_version: t.ip_version.map(|f| f.to_string()),
                bind_interface: t.bind_interface.as_ref().map(name),
                resolver_name: t.resolver_name.clone(),
                unknown: UnknownKeys::default(),
            };
            (n.clone(), entry)
        });
        let sessions = config.sessions.iter().map(|(n, s)| {
            let entry = PartialSession {
                tunnel_name: Some(s.tunnel_name.clone()),
                session_id: Some(s.session_id.into()),
                peer_session_id: s.peer_session_id.map(Into::into),
                interface_name: Some(name(&s.interface_name)),
                interface_hwaddr: s.interface_hwaddr.map(|a| a.to_string()),
                cookie: s.cookie.map(|c| text::to_hex(c.as_bytes())),
                peer_cookie: s.peer_cookie.map(|c| text::to_hex(c.as_bytes())),
                unknown: UnknownKeys::default(),
            };
            (n.clone(), entry)
        });
        PartialConfig {
            host: PartialHost {
                fix_bindv6only: config.host.fix_bindv6only,
                unknown: UnknownKeys::default(),
            },
            resolvers: resolvers.collect(),
            tunnels: tunnels.collect(),
            sessions: sessions.collect(),
            unknown: UnknownKeys::default(),
            labeled: Vec::new(),
        }
    }
}

/// The kind of an entry a problem names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntryKind {
    /// A `tunnels` entry.
    Tunnel,
    /// A `sessions` entry.
    Session,
    /// A `resolvers` entry.
    Resolver,
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::Tunnel => "tunnel",
            EntryKind::Session => "session",
            EntryKind::Resolver => "resolver",
        })
    }
}

/// What became of the entry or key a problem names (C10, C12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Effect {
    /// A tolerated mistake: the entry is applied with the value dropped
    /// (no peer, the kernel's hardware address, the key ignored).
    Corrected,
    /// A hard mistake of a new entry: left out.
    LeftOut,
    /// A hard mistake of an entry of the accepted configuration: its
    /// values in force are kept.
    KeptPrevious,
    /// Values in force that no longer fit: the reload is refused.
    Refused,
    /// An unknown key: ignored.
    Ignored,
}

/// Where a problem is.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProblemKind {
    /// An entry, and the field at fault where there is one.
    Entry {
        /// The entry's kind.
        kind: EntryKind,
        /// The entry's configuration name.
        name: String,
        /// The field at fault; `None` for the name itself.
        field: Option<&'static str>,
    },
    /// A key of a document.
    Document {
        /// The file, when the program named it with
        /// [`PartialConfig::set_source`].
        source: Option<PathBuf>,
        /// The key's path, table by table.
        path: Vec<String>,
    },
}

/// One problem of a conversion (C15). Its `Display` is the message the
/// daemon logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    kind: ProblemKind,
    effect: Effect,
    message: String,
}

impl Problem {
    fn entry(kind: EntryKind, name: &str, mistake: Mistake, effect: Effect) -> Self {
        Problem {
            kind: ProblemKind::Entry {
                kind,
                name: name.to_owned(),
                field: mistake.field,
            },
            effect,
            message: mistake.message,
        }
    }

    /// Where the problem is.
    pub fn kind(&self) -> &ProblemKind {
        &self.kind
    }

    /// What became of the entry or key.
    pub fn effect(&self) -> Effect {
        self.effect
    }

    /// The underlying error.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The problem without its effect.
    fn subject(&self) -> String {
        match &self.kind {
            ProblemKind::Entry { kind, name, field } => match field {
                Some(field) => format!("{kind} {name:?}, {field}: {}", self.message),
                None => format!("{kind} {name:?}: {}", self.message),
            },
            ProblemKind::Document { source, path } => {
                let path = key_path(path);
                match source {
                    Some(source) => format!("{}: {path}: {}", source.display(), self.message),
                    None => format!("{path}: {}", self.message),
                }
            }
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let effect = match (self.effect, &self.kind) {
            (
                Effect::Corrected,
                ProblemKind::Entry {
                    field: Some("remote_addr" | "ip_version"),
                    ..
                },
            ) => "applied without a peer",
            (
                Effect::Corrected,
                ProblemKind::Entry {
                    field: Some("interface_hwaddr"),
                    ..
                },
            ) => "applied with the hardware address the kernel assigns",
            (Effect::Corrected, _) => "applied, the key ignored",
            (Effect::LeftOut, _) => "left out",
            (Effect::KeptPrevious, _) => "the values in force are kept",
            (Effect::Refused, _) => "the reload is refused",
            (Effect::Ignored, _) => "ignored",
        };
        write!(f, "{}; {effect}", self.subject())
    }
}

/// `tunnels.a.foo`, with segments that are no bare TOML key quoted.
fn key_path(path: &[String]) -> String {
    let bare = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    path.iter()
        .map(|s| if bare(s) { s.clone() } else { format!("{s:?}") })
        .collect::<Vec<_>>()
        .join(".")
}
