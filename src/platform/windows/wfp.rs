//! WFP backend: a persistent provider and max-weight sublayer holding the filters that
//! `firewall::wfp` compiles. Persistent filters are enforced by BFE across daemon exits
//! and reboots until removed.

use super::{from_wide, interface_luid, wide};
use crate::config::Config;
use crate::firewall::wfp::{compile, describe, Action, Cond, Filter, Layer, Plan};
use crate::firewall::{Firewall, FwState};
use crate::policy::Policy;
use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
    FWP_E_SUBLAYER_NOT_FOUND, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetTcpTable2, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPTABLE2,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

struct Keys {
    provider: GUID,
    sublayer: GUID,
}

/// The live objects. Fixed so every run, and uninstall, finds what earlier runs left.
const LIVE: Keys = Keys {
    provider: GUID::from_u128(0x6b0a3c52_1f4e_4d8b_9a37_d2c41e0f7a01),
    sublayer: GUID::from_u128(0x6b0a3c52_1f4e_4d8b_9a37_d2c41e0f7a02),
};
/// Throwaway objects for `validate`, only ever added inside an aborted transaction.
const CHECK: Keys = Keys {
    provider: GUID::from_u128(0x6b0a3c52_1f4e_4d8b_9a37_d2c41e0f7a03),
    sublayer: GUID::from_u128(0x6b0a3c52_1f4e_4d8b_9a37_d2c41e0f7a04),
};

fn same(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}

fn layer_of(key: &GUID) -> Option<Layer> {
    Layer::ALL.into_iter().find(|&l| same(&layer_key(l), key))
}

fn layer_key(l: Layer) -> GUID {
    match l {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::AcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::AcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// Entries per enumeration call.
const BATCH: u32 = 512;

fn check(rc: u32, what: impl FnOnce() -> String) -> Result<()> {
    if rc != NO_ERROR {
        bail!("{}: WFP error {rc:#010x}", what());
    }
    Ok(())
}

struct Engine(HANDLE);

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: opened by FwpmEngineOpen0, closed once. A dynamic session's objects go too.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// App ID blobs allocated by WFP, freed when the batch that used them is done.
#[derive(Default)]
struct AppIds(HashMap<PathBuf, *mut FWP_BYTE_BLOB>);

impl AppIds {
    fn get(&mut self, p: &Path) -> Result<*mut FWP_BYTE_BLOB> {
        if let Some(&blob) = self.0.get(p) {
            return Ok(blob);
        }
        let name = wide(p);
        let mut blob = null_mut();
        // SAFETY: `name` is NUL-terminated; WFP allocates `blob`, freed in Drop.
        check(
            unsafe { FwpmGetAppIdFromFileName0(name.as_ptr(), &mut blob) },
            || format!("app ID of {}", p.display()),
        )?;
        self.0.insert(p.to_path_buf(), blob);
        Ok(blob)
    }
}

impl Drop for AppIds {
    fn drop(&mut self) {
        for &blob in self.0.values() {
            let mut raw = blob.cast();
            // SAFETY: allocated by FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0(&mut raw) };
        }
    }
}

/// Condition values WFP reads through pointers; kept alive until the filter is added.
/// Boxed so the pointers stay valid when a Vec grows.
#[derive(Default)]
#[allow(clippy::vec_box)]
struct Backing {
    u64s: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
}

impl Backing {
    fn condition(&mut self, c: &Cond, apps: &mut AppIds) -> Result<FWPM_FILTER_CONDITION0> {
        let mut fc = FWPM_FILTER_CONDITION0 {
            matchType: FWP_MATCH_EQUAL,
            ..Default::default()
        };
        let mut luid = |fc: &mut FWPM_FILTER_CONDITION0, field, id: u64| {
            let mut b = Box::new(id);
            fc.fieldKey = field;
            fc.conditionValue.r#type = FWP_UINT64;
            fc.conditionValue.Anonymous.uint64 = &mut *b;
            self.u64s.push(b);
        };
        match c {
            Cond::Loopback => {
                fc.fieldKey = FWPM_CONDITION_FLAGS;
                fc.matchType = FWP_MATCH_FLAGS_ALL_SET;
                fc.conditionValue.r#type = FWP_UINT32;
                fc.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            }
            Cond::LocalInterface(id) => luid(&mut fc, FWPM_CONDITION_IP_LOCAL_INTERFACE, *id),
            Cond::App(p) => {
                fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                fc.conditionValue.Anonymous.byteBlob = apps.get(p)?;
            }
            Cond::Protocol(n) => {
                fc.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                fc.conditionValue.r#type = FWP_UINT8;
                fc.conditionValue.Anonymous.uint8 = *n;
            }
            // FWPM_CONDITION_ICMP_TYPE is an alias of the local port field.
            Cond::LocalPort(n) | Cond::RemotePort(n) => {
                fc.fieldKey = if matches!(c, Cond::LocalPort(_)) {
                    FWPM_CONDITION_IP_LOCAL_PORT
                } else {
                    FWPM_CONDITION_IP_REMOTE_PORT
                };
                fc.conditionValue.r#type = FWP_UINT16;
                fc.conditionValue.Anonymous.uint16 = *n;
            }
            Cond::Remote(net) => {
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                self.address(&mut fc, net);
            }
        }
        Ok(fc)
    }

    fn address(&mut self, fc: &mut FWPM_FILTER_CONDITION0, net: &IpNet) {
        match net {
            IpNet::V4(n) => {
                let bits = u32::from(n.prefix_len());
                let mut b = Box::new(FWP_V4_ADDR_AND_MASK {
                    // Host byte order, as WFP expects for v4 masks.
                    addr: u32::from(n.network()),
                    mask: u32::MAX.checked_shl(32 - bits).unwrap_or(0),
                });
                fc.conditionValue.r#type = FWP_V4_ADDR_MASK;
                fc.conditionValue.Anonymous.v4AddrMask = &mut *b;
                self.v4.push(b);
            }
            IpNet::V6(n) => {
                let mut b = Box::new(FWP_V6_ADDR_AND_MASK {
                    addr: n.network().octets(),
                    prefixLength: n.prefix_len(),
                });
                fc.conditionValue.r#type = FWP_V6_ADDR_MASK;
                fc.conditionValue.Anonymous.v6AddrMask = &mut *b;
                self.v6.push(b);
            }
        }
    }
}

struct Existing {
    id: u64,
    /// `None` for a layer this version does not use, i.e. left by an older one.
    layer: Option<Layer>,
    block: bool,
    conds: u32,
    name: String,
    boot: bool,
    disabled: bool,
}

impl Engine {
    fn open(dynamic: bool) -> Result<Self> {
        let session = FWPM_SESSION0 {
            flags: if dynamic {
                FWPM_SESSION_FLAG_DYNAMIC
            } else {
                0
            },
            txnWaitTimeoutInMSec: 10_000,
            ..Default::default()
        };
        let mut h = null_mut();
        // SAFETY: valid session struct and out pointer; the handle is closed in Drop.
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut h) },
            || "opening the filter engine (is BFE running?)".into(),
        )?;
        Ok(Engine(h))
    }

    fn begin(&self) -> Result<()> {
        // SAFETY: open engine handle.
        check(unsafe { FwpmTransactionBegin0(self.0, 0) }, || {
            "starting a WFP transaction".into()
        })
    }

    fn abort(&self) {
        // SAFETY: open engine handle with a transaction in progress.
        unsafe { FwpmTransactionAbort0(self.0) };
    }

    /// All-or-nothing: on error nothing of `f` reaches the kernel.
    fn transaction(&self, f: impl FnOnce(&Self) -> Result<()>) -> Result<()> {
        self.begin()?;
        match f(self) {
            // SAFETY: open engine handle with a transaction in progress.
            Ok(()) => check(unsafe { FwpmTransactionCommit0(self.0) }, || {
                "committing the WFP transaction".into()
            }),
            Err(e) => {
                self.abort();
                Err(e)
            }
        }
    }

    fn add_provider(&self, keys: &Keys, persistent: bool) -> Result<()> {
        let name = wide("daemon-killer");
        let desc = wide("Fail-closed Clash TUN kill switch");
        let service = wide(super::service::SERVICE);
        let p = FWPM_PROVIDER0 {
            providerKey: keys.provider,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: desc.as_ptr().cast_mut(),
            },
            flags: if persistent {
                FWPM_PROVIDER_FLAG_PERSISTENT
            } else {
                0
            },
            // BFE disables a provider's filters at startup without an associated
            // auto-start service, even when the filters themselves are persistent.
            serviceName: service.as_ptr().cast_mut(),
            ..Default::default()
        };
        // SAFETY: strings outlive the call.
        let rc = unsafe { FwpmProviderAdd0(self.0, &p, null_mut()) };
        if rc == FWP_E_ALREADY_EXISTS as u32 {
            return Ok(());
        }
        check(rc, || "adding the WFP provider".into())
    }

    fn add_sublayer(&self, keys: &Keys, persistent: bool) -> Result<()> {
        let name = wide("daemon-killer");
        let desc = wide("Only the Clash TUN may reach the internet");
        let mut provider = keys.provider;
        let s = FWPM_SUBLAYER0 {
            subLayerKey: keys.sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: desc.as_ptr().cast_mut(),
            },
            flags: if persistent {
                FWPM_SUBLAYER_FLAG_PERSISTENT
            } else {
                0
            },
            providerKey: &mut provider,
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: strings and `provider` outlive the call.
        let rc = unsafe { FwpmSubLayerAdd0(self.0, &s, null_mut()) };
        if rc == FWP_E_ALREADY_EXISTS as u32 {
            return Ok(());
        }
        check(rc, || "adding the WFP sublayer".into())
    }

    fn add_filter(&self, keys: &Keys, f: &Filter, flags: u32, apps: &mut AppIds) -> Result<()> {
        let mut backing = Backing::default();
        let mut conds = f
            .conds
            .iter()
            .map(|c| backing.condition(c, apps))
            .collect::<Result<Vec<_>>>()?;
        let name = wide(f.name);
        let mut provider = keys.provider;
        let mut filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr().cast_mut(),
                description: null_mut(),
            },
            // A hard block: lower-priority sublayers cannot override it.
            flags: flags
                | match f.action {
                    Action::Block => FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                    Action::Permit => 0,
                },
            providerKey: &mut provider,
            layerKey: layer_key(f.layer),
            subLayerKey: keys.sublayer,
            numFilterConditions: conds.len() as u32,
            filterCondition: if conds.is_empty() {
                null_mut()
            } else {
                conds.as_mut_ptr()
            },
            ..Default::default()
        };
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = f.action.weight();
        filter.action.r#type = match f.action {
            Action::Permit => FWP_ACTION_PERMIT,
            Action::Block => FWP_ACTION_BLOCK,
        };
        let mut id = 0;
        // SAFETY: every pointer in `filter` points into locals or `backing`/`apps`, all alive.
        check(
            unsafe { FwpmFilterAdd0(self.0, &filter, null_mut(), &mut id) },
            || format!("adding filter {:?} on {}", f.name, f.layer.name()),
        )
    }

    /// Our filters in the layers this version uses. Cheap enough for every daemon tick.
    fn ours(&self, keys: &Keys) -> Result<Vec<Existing>> {
        let mut out = Vec::new();
        for layer in Layer::ALL {
            self.filters_in(keys, &layer_key(layer), &mut out)?;
        }
        Ok(out)
    }

    /// Every filter in our sublayer or by our provider in one layer, including foreign ones
    /// slipped into our sublayer (they would outrank the block).
    fn filters_in(&self, keys: &Keys, layer_key: &GUID, out: &mut Vec<Existing>) -> Result<()> {
        let layer = layer_of(layer_key);
        let what = || format!("enumerating {}", layer.map_or("a WFP layer", Layer::name));
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: *layer_key,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            // Boot filters are excluded by default, but down/pause/uninstall
            // must remove them along with the runtime filters.
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            actionMask: u32::MAX,
            ..Default::default()
        };
        let mut h = null_mut();
        // SAFETY: valid template and out handle, destroyed below.
        check(
            unsafe { FwpmFilterCreateEnumHandle0(self.0, &template, &mut h) },
            what,
        )?;
        let result = (|| -> Result<()> {
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
                let mut n = 0u32;
                // SAFETY: WFP allocates `entries`; freed below.
                check(
                    unsafe { FwpmFilterEnum0(self.0, h, BATCH, &mut entries, &mut n) },
                    what,
                )?;
                for i in 0..n as usize {
                    // SAFETY: WFP returned `n` valid filter pointers.
                    let f = unsafe { &**entries.add(i) };
                    let by_us = !f.providerKey.is_null()
                        // SAFETY: checked non-null; points into the WFP allocation.
                        && same(unsafe { &*f.providerKey }, &keys.provider);
                    if by_us || same(&f.subLayerKey, &keys.sublayer) {
                        out.push(Existing {
                            id: f.filterId,
                            layer,
                            block: f.action.r#type == FWP_ACTION_BLOCK,
                            conds: f.numFilterConditions,
                            name: from_wide(f.displayData.name),
                            boot: f.flags & FWPM_FILTER_FLAG_BOOTTIME != 0,
                            disabled: f.flags & FWPM_FILTER_FLAG_DISABLED != 0,
                        });
                    }
                }
                if !entries.is_null() {
                    let mut raw = entries.cast();
                    // SAFETY: allocated by FwpmFilterEnum0.
                    unsafe { FwpmFreeMemory0(&mut raw) };
                }
                if n < BATCH {
                    return Ok(());
                }
            }
        })();
        // SAFETY: created above.
        unsafe { FwpmFilterDestroyEnumHandle0(self.0, h) };
        result
    }

    /// Every layer BFE knows about.
    fn all_layers(&self) -> Result<Vec<GUID>> {
        let mut h = null_mut();
        // SAFETY: a null template enumerates all layers; the handle is destroyed below.
        check(
            unsafe { FwpmLayerCreateEnumHandle0(self.0, null(), &mut h) },
            || "enumerating WFP layers".into(),
        )?;
        let mut keys = Vec::new();
        let result = (|| -> Result<()> {
            loop {
                let mut entries: *mut *mut FWPM_LAYER0 = null_mut();
                let mut n = 0u32;
                // SAFETY: WFP allocates `entries`; freed below.
                check(
                    unsafe { FwpmLayerEnum0(self.0, h, BATCH, &mut entries, &mut n) },
                    || "enumerating WFP layers".into(),
                )?;
                // SAFETY: WFP returned `n` valid layer pointers.
                keys.extend((0..n as usize).map(|i| unsafe { (**entries.add(i)).layerKey }));
                if !entries.is_null() {
                    let mut raw = entries.cast();
                    // SAFETY: allocated by FwpmLayerEnum0.
                    unsafe { FwpmFreeMemory0(&mut raw) };
                }
                if n < BATCH {
                    return Ok(());
                }
            }
        })();
        // SAFETY: created above.
        unsafe { FwpmLayerDestroyEnumHandle0(self.0, h) };
        result.map(|()| keys)
    }

    /// Searches every layer, not only the ones this version uses: whatever an older version
    /// left in our sublayer must go too, or deleting the sublayer fails and `down` with it.
    /// So a changed rule layout needs no migration.
    fn delete_ours(&self, keys: &Keys) -> Result<()> {
        let mut found = Vec::new();
        for layer in self.all_layers()? {
            if let Err(e) = self.filters_in(keys, &layer, &mut found) {
                // Our own layers must enumerate. Others may refuse; a filter of ours left
                // there still surfaces as a failure to delete the sublayer.
                if layer_of(&layer).is_some() {
                    return Err(e);
                }
                log::debug!("{e:#}");
            }
        }
        for f in found {
            // SAFETY: open engine handle.
            let rc = unsafe { FwpmFilterDeleteById0(self.0, f.id) };
            if rc != FWP_E_FILTER_NOT_FOUND as u32 {
                check(rc, || format!("deleting filter {:?}", f.name))?;
            }
        }
        Ok(())
    }

    /// Remove owned objects inside the caller's transaction. Recreating the provider
    /// also upgrades older installations that did not associate it with our service.
    fn remove_objects(&self, keys: &Keys) -> Result<()> {
        self.delete_ours(keys)?;
        // SAFETY: open engine handle; only our fixed keys are removed.
        let rc = unsafe { FwpmSubLayerDeleteByKey0(self.0, &keys.sublayer) };
        if rc != FWP_E_SUBLAYER_NOT_FOUND as u32 {
            check(rc, || "deleting the WFP sublayer".into())?;
        }
        // SAFETY: open engine handle; dependent objects were removed above.
        let rc = unsafe { FwpmProviderDeleteByKey0(self.0, &keys.provider) };
        if rc != FWP_E_PROVIDER_NOT_FOUND as u32 {
            check(rc, || "deleting the WFP provider".into())?;
        }
        Ok(())
    }

    fn sublayer_exists(&self, keys: &Keys) -> Result<bool> {
        let mut s: *mut FWPM_SUBLAYER0 = null_mut();
        // SAFETY: WFP allocates `s`; freed below.
        let rc = unsafe { FwpmSubLayerGetByKey0(self.0, &keys.sublayer, &mut s) };
        if rc == FWP_E_SUBLAYER_NOT_FOUND as u32 {
            return Ok(false);
        }
        check(rc, || "looking up the WFP sublayer".into())?;
        let mut raw = s.cast();
        // SAFETY: allocated by FwpmSubLayerGetByKey0.
        unsafe { FwpmFreeMemory0(&mut raw) };
        Ok(true)
    }

    fn install(&self, keys: &Keys, persistent: bool, filters: &[Filter], flags: u32) -> Result<()> {
        self.add_provider(keys, persistent)?;
        self.add_sublayer(keys, persistent)?;
        let mut apps = AppIds::default();
        for f in filters {
            self.add_filter(keys, f, flags, &mut apps)?;
        }
        Ok(())
    }
}

pub struct Wfp {
    boot: bool,
}

impl Wfp {
    pub fn new(cfg: &Config) -> Self {
        Wfp {
            boot: cfg.boot_time_block,
        }
    }

    fn plan(&self, policy: &Policy) -> Plan {
        compile(policy, &interface_luid, self.boot)
    }
}

impl Firewall for Wfp {
    const VALIDATE_NEEDS_ELEVATION: bool = true;

    fn render(&self, policy: &Policy) -> String {
        describe(&self.plan(policy))
    }

    /// Adds everything to throwaway objects in a dynamic session, then aborts.
    fn validate(&self, policy: &Policy) -> Result<()> {
        let plan = self.plan(policy);
        let e = Engine::open(true)?;
        e.begin()?;
        let all: Vec<Filter> = plan.filters.iter().chain(&plan.boot).cloned().collect();
        let r = e.install(&CHECK, false, &all, 0);
        e.abort();
        r
    }

    fn state(&self) -> Result<FwState> {
        let e = Engine::open(false)?;
        let present = e.sublayer_exists(&LIVE)?;
        let ours = e.ours(&LIVE)?;
        let blocking = ours.iter().any(|f| {
            f.layer == Some(Layer::ConnectV4) && f.block && f.conds == 0 && !f.boot && !f.disabled
        });
        let mut lines: Vec<String> = ours
            .iter()
            .map(|f| {
                format!(
                    "{} {} {} {}{}{}",
                    f.layer.map_or("other", Layer::name),
                    if f.block { "block" } else { "permit" },
                    f.conds,
                    f.name,
                    if f.boot { " (boot)" } else { "" },
                    if f.disabled { " (disabled)" } else { "" }
                )
            })
            .collect();
        lines.sort();
        Ok(FwState {
            active: present,
            blocking,
            fingerprint: lines.join("\n"),
            summary: format!(
                "wfp sublayer {}, {} filters",
                if present { "present" } else { "MISSING" },
                ours.len()
            ),
        })
    }

    /// Replace all our filters in one transaction, so there is no gap and no half state.
    fn apply(&self, policy: &Policy) -> Result<()> {
        let plan = self.plan(policy);
        for name in &plan.missing {
            log::warn!("interface {name:?} not present; its traffic stays blocked");
        }
        let e = Engine::open(false)?;
        e.transaction(|e| {
            e.remove_objects(&LIVE)?;
            e.install(&LIVE, true, &plan.filters, FWPM_FILTER_FLAG_PERSISTENT)
        })?;
        if !plan.boot.is_empty() {
            let r =
                e.transaction(|e| e.install(&LIVE, true, &plan.boot, FWPM_FILTER_FLAG_BOOTTIME));
            if let Err(err) = r {
                log::warn!("boot-time filters not installed: {err:#}");
            }
        }
        Ok(())
    }

    /// WFP authorises at connect/accept, so flows that predate the block keep going until
    /// ALE re-authorises them. Reset established IPv4 TCP explicitly, like pf's state flush;
    /// IPv6 TCP and UDP have no reset API and rely on re-authorisation.
    fn revoke_connections(&self) -> Result<()> {
        let mut size = 0u32;
        // SAFETY: size query with a null buffer.
        unsafe { GetTcpTable2(null_mut(), &mut size, 0) };
        // Headroom for connections opened between the two calls; u32 keeps the alignment.
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 256];
        let mut size = (buf.len() * 4) as u32;
        // SAFETY: `buf` is `size` bytes and 4-aligned.
        let rc = unsafe { GetTcpTable2(buf.as_mut_ptr().cast(), &mut size, 0) };
        check(rc, || "reading the TCP table".into())?;
        let table = buf.as_ptr().cast::<MIB_TCPTABLE2>();
        // SAFETY: the table header is followed by dwNumEntries rows inside `buf`.
        let rows = unsafe {
            std::slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize)
        };
        let loopback = |addr: u32| addr.to_ne_bytes()[0] == 127;
        let mut cut = 0;
        for r in rows {
            if r.dwState != MIB_TCP_STATE_ESTAB as u32
                || loopback(r.dwLocalAddr)
                || loopback(r.dwRemoteAddr)
            {
                continue;
            }
            let row = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 {
                    dwState: MIB_TCP_STATE_DELETE_TCB as u32,
                },
                dwLocalAddr: r.dwLocalAddr,
                dwLocalPort: r.dwLocalPort,
                dwRemoteAddr: r.dwRemoteAddr,
                dwRemotePort: r.dwRemotePort,
            };
            // SAFETY: valid row; failures (connection already gone) are ignored.
            if unsafe { SetTcpEntry(&row) } == NO_ERROR {
                cut += 1;
            }
        }
        log::info!("reset {cut} IPv4 TCP connections");
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        let e = Engine::open(false)?;
        e.transaction(|e| e.remove_objects(&LIVE))
            .context("removing WFP filters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the native condition mapping against the layers on this Windows host.
    /// The transaction is aborted, so no rules become active. Requires elevation.
    #[test]
    #[ignore = "requires an administrator terminal and the Base Filtering Engine"]
    fn native_rules_validate() {
        let cfg = Config {
            core_program: Some(std::env::current_exe().unwrap()),
            tun_device: "Loopback Pseudo-Interface 1".into(),
            egress: crate::config::Egress::Core,
            ..Config::default()
        };
        Wfp::new(&cfg).validate(&Policy::build(&cfg, &[])).unwrap();
    }

    #[test]
    #[ignore = "requires an administrator terminal and the Base Filtering Engine"]
    fn native_boot_filters_enumerate() {
        let cfg = Config {
            core_program: Some(std::env::current_exe().unwrap()),
            boot_time_block: true,
            ..Config::default()
        };
        let plan = Wfp::new(&cfg).plan(&Policy::build(&cfg, &[]));
        let engine = Engine::open(false).unwrap();
        engine.begin().unwrap();
        let result = engine
            .install(&CHECK, true, &plan.boot, FWPM_FILTER_FLAG_BOOTTIME)
            .and_then(|()| engine.ours(&CHECK));
        engine.abort();
        let filters = result.unwrap();
        assert_eq!(filters.len(), plan.boot.len());
        assert!(filters.iter().all(|f| f.boot));
    }

    /// A filter an older version left on a layer this one does not use (IPFORWARD) must
    /// not keep the sublayer, and so `down`, from being removed.
    #[test]
    #[ignore = "requires an administrator terminal and the Base Filtering Engine"]
    fn native_cleanup_finds_filters_on_unused_layers() {
        let engine = Engine::open(false).unwrap();
        engine.begin().unwrap();
        let result = (|| -> Result<()> {
            engine.install(&CHECK, true, &[], 0)?;
            let name = wide("daemon-killer stray layer test");
            let mut provider = CHECK.provider;
            let mut stray = FWPM_FILTER0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr().cast_mut(),
                    ..Default::default()
                },
                providerKey: &mut provider,
                layerKey: FWPM_LAYER_IPFORWARD_V4,
                subLayerKey: CHECK.sublayer,
                ..Default::default()
            };
            stray.action.r#type = FWP_ACTION_BLOCK;
            let mut id = 0;
            // SAFETY: pointers into locals that outlive the call; aborted below.
            check(
                unsafe { FwpmFilterAdd0(engine.0, &stray, null_mut(), &mut id) },
                || "adding the stray filter".into(),
            )?;
            anyhow::ensure!(
                engine.ours(&CHECK)?.is_empty(),
                "IPFORWARD is not a used layer"
            );
            engine.remove_objects(&CHECK)?;
            anyhow::ensure!(!engine.sublayer_exists(&CHECK)?, "sublayer survived");
            Ok(())
        })();
        engine.abort();
        result.unwrap();
    }

    #[test]
    #[ignore = "requires an administrator terminal and the Base Filtering Engine"]
    fn native_provider_service_migration() {
        let engine = Engine::open(false).unwrap();
        engine.begin().unwrap();
        let result = (|| -> Result<(String, usize)> {
            let name = wide("daemon-killer legacy provider test");
            let legacy = FWPM_PROVIDER0 {
                providerKey: CHECK.provider,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_ptr().cast_mut(),
                    ..Default::default()
                },
                flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                ..Default::default()
            };
            // SAFETY: valid strings and provider; all changes are aborted below.
            check(
                unsafe { FwpmProviderAdd0(engine.0, &legacy, null_mut()) },
                || "adding the legacy test provider".into(),
            )?;
            let cfg = Config::default();
            let plan = Wfp::new(&cfg).plan(&Policy::build(&cfg, &[]));
            engine.install(&CHECK, true, &plan.filters, FWPM_FILTER_FLAG_PERSISTENT)?;
            engine.remove_objects(&CHECK)?;
            engine.install(&CHECK, true, &plan.filters, FWPM_FILTER_FLAG_PERSISTENT)?;
            let mut provider: *mut FWPM_PROVIDER0 = null_mut();
            // SAFETY: WFP allocates provider, freed after copying the service name.
            check(
                unsafe { FwpmProviderGetByKey0(engine.0, &CHECK.provider, &mut provider) },
                || "reading the migrated provider".into(),
            )?;
            let service = from_wide(unsafe { (*provider).serviceName });
            let mut raw = provider.cast();
            unsafe { FwpmFreeMemory0(&mut raw) };
            let count = engine.ours(&CHECK)?.len();
            anyhow::ensure!(count == plan.filters.len(), "migration lost filters");
            Ok((service, count))
        })();
        engine.abort();
        let (service, count) = result.unwrap();
        assert_eq!(service, super::super::service::SERVICE);
        assert!(count > 0);
    }
}
