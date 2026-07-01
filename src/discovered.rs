//! The **discovered-defaults tier** — environment-discovered layered defaults,
//! merged into a config chain *above* the developer's prescribed defaults but
//! *below* operator file/env config.
//!
//! A [`DiscoveryLayer`] inspects the running environment along one axis
//! (platform, cloud, orchestrator, instance class, tenancy, …) and emits a
//! *partial* config [`Dict`] — only the keys that axis wants to influence,
//! empty when its axis is undetectable. [`compose`] deep-merges an ordered
//! stack of layers coarse→specific (a more-specific layer overrides a coarser
//! one per leaf key), and [`crate::ProviderChain::with_discovered`] merges the
//! composed dict into the figment chain at the discovered-tier precedence:
//!
//! ```text
//! serde-defaults → prescribed_default() → DISCOVERED → file → env
//!    (floor)         (developer opinion)   (this tier)   (operator wins)
//! ```
//!
//! `kanchi` (the fleet environment-probe primitive) provides the typed axis
//! facts a layer reads; this module owns only the *composition* — kept here so
//! the merge precedence and the deep-merge semantics live in one place beside
//! [`crate::ProviderChain`].

use std::collections::BTreeMap;

use figment::value::{Dict, Value};

/// One environment axis that contributes a partial defaults layer.
///
/// Implementors read the environment (typically via `kanchi` probes) and
/// return only the config keys they want to shape. An axis that can't answer
/// returns an empty [`Dict`] — the clean degenerate (it contributes nothing,
/// so the next tier shows through), never a guess.
pub trait DiscoveryLayer {
    /// A stable, human-facing name for this layer (provenance / debugging).
    fn name(&self) -> &'static str;
    /// The partial config this layer contributes, given the current
    /// environment. Empty ⇒ this axis is undetectable / has no opinion.
    fn discover(&self) -> Dict;
}

/// Deep-merge `overlay` into `base`: nested dicts recurse (per-leaf-key,
/// overlay wins), every other value — scalars **and arrays** — replaces
/// wholesale.
///
/// This matches the observable semantics of figment's own `.merge()` (used by
/// [`crate::ProviderChain::with_discovered`]) for the cases config layers
/// actually hit: dict+dict recurses, scalar/array replaces (figment's
/// `Order::Merge` likewise replaces arrays — only `adjoin`/`admerge` concatenate,
/// which the chain never uses). So a coarse layer and a specific layer combine
/// the way the discovered tier later combines with the file tier. One caveat:
/// [`compose`] collapses all layers into one dict *before* the single figment
/// merge, so under a cross-layer key whose *type* changes between layers the
/// grouped result can differ from a strict sequential per-layer merge — benign
/// for the type-consistent axes a [`DiscoveryLayer`] emits.
pub fn deep_merge(base: &mut Dict, overlay: Dict) {
    for (key, incoming) in overlay {
        match (base.get_mut(&key), incoming) {
            // Two maps at the same key: recurse so sibling keys survive.
            (Some(Value::Dict(_, base_inner)), Value::Dict(_, over_inner)) => {
                deep_merge(base_inner, over_inner);
            }
            // Anything else: the overlay value wins wholesale.
            (_, incoming) => {
                base.insert(key, incoming);
            }
        }
    }
}

/// Compose an ordered stack of [`DiscoveryLayer`]s into one partial config
/// dict.
///
/// Layers are applied **coarse→specific**: later layers override earlier ones
/// per leaf key (deep-merged), so order the slice from the most general axis
/// (platform) to the most specific (instance class / tenancy). Empty-dict
/// layers contribute nothing — an undetectable axis is invisible, not a
/// clobber.
///
/// This is the [`compose_with_provenance`] projection that discards
/// attribution: `compose(layers) == compose_with_provenance(layers).dict`
/// for every input. Callers that need to answer "which layer wrote this
/// leaf?" (config-show renderers, discovered-tier attribution) reach for
/// [`compose_with_provenance`] directly; callers that only need the merged
/// [`Dict`] stay on this projection so the attribution [`BTreeMap`] is
/// dropped at the boundary.
#[must_use]
pub fn compose(layers: &[&dyn DiscoveryLayer]) -> Dict {
    compose_with_provenance(layers).dict
}

/// The provenance names of an ordered layer stack, in application order.
#[must_use]
pub fn layer_names(layers: &[&dyn DiscoveryLayer]) -> Vec<&'static str> {
    layers.iter().map(|layer| layer.name()).collect()
}

/// Per-leaf provenance for a composed [`DiscoveryLayer`] stack: the name
/// of the winning layer at every leaf path of the merged dict.
///
/// Keys are dotted-path components (`Vec<String>`, not a flat `"a.b"`
/// string) so keys containing `.` roundtrip unambiguously. Ordered
/// lexicographically ([`BTreeMap`] iteration), giving deterministic
/// iteration for debug dumps, config-show renderers, and tests. A
/// "leaf" is any non-dict value — scalars, arrays, and figment
/// [`Value::Empty`] all attribute at their own path; sibling keys
/// under a common dict prefix are attributed independently, so two
/// layers that touch different leaves under the same subtree each keep
/// credit for what they wrote.
///
/// This is the [`ConfigSource::Discovered`]-flavored substrate for the
/// future discovery-provenance thread noted on
/// [`crate::ProviderChain::with_discovered`]: a downstream store can
/// consult [`LayerAttribution::layer_of`] to answer "which
/// [`DiscoveryLayer`] shaped this leaf?" without re-running the
/// discovery pass.
///
/// [`ConfigSource::Discovered`]: crate::ConfigSource
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LayerAttribution {
    inner: BTreeMap<Vec<String>, &'static str>,
}

impl LayerAttribution {
    /// Number of leaves attributed. Zero when every layer emitted an
    /// empty [`Dict`] (or no layers were composed).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no leaves are attributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Name of the winning [`DiscoveryLayer`] at the leaf named by
    /// dotted `path`, or [`None`] if `path` names no leaf in the
    /// composed dict.
    #[must_use]
    pub fn layer_of(&self, path: &[&str]) -> Option<&'static str> {
        // BTreeMap keyed on Vec<String> won't accept &[&str] as a
        // Borrow key, so walk once with the equal-len-and-elems test.
        // Leaf count is bounded by the discovered dict's key count
        // (config keys, not row counts), so linear scan is fine.
        self.inner.iter().find_map(|(p, layer)| {
            (p.len() == path.len() && p.iter().zip(path).all(|(a, b)| a == b)).then_some(*layer)
        })
    }

    /// Sorted iterator over `(path, layer)` entries. Ordering is
    /// lexicographic by path — the [`BTreeMap`] iteration order.
    pub fn iter(&self) -> impl Iterator<Item = (&[String], &'static str)> + '_ {
        self.inner.iter().map(|(p, l)| (p.as_slice(), *l))
    }
}

/// The result of composing a stack of [`DiscoveryLayer`]s with per-leaf
/// provenance tracking.
///
/// `dict` is byte-identical to [`compose`]`(layers)` — the same
/// primitive powers both — and `attribution` records the name of the
/// [`DiscoveryLayer`] that last wrote each leaf. Peer to [`compose`]
/// on the no-attribution path.
///
/// `PartialEq` but not `Eq`: figment's [`Value`] does not implement
/// [`Eq`] (its floating-point variants preclude reflexive equality
/// on `NaN`), so [`Dict`] and therefore [`DiscoveryComposition`] carry
/// only the partial contract. [`LayerAttribution`] is [`Eq`]
/// independently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryComposition {
    /// The merged dict. Equals `compose(layers)` for every input.
    pub dict: Dict,
    /// One entry per leaf in `dict`, naming the winning layer.
    pub attribution: LayerAttribution,
}

/// Compose an ordered stack of [`DiscoveryLayer`]s while tracking
/// per-leaf provenance — the name of the layer that last wrote each
/// leaf in the merged dict.
///
/// Layers are applied coarse→specific (same order as [`compose`]).
/// The returned [`DiscoveryComposition`] carries both the merged
/// [`Dict`] and a [`LayerAttribution`] keyed by dotted-path
/// components. [`compose`] is `compose_with_provenance(...).dict` by
/// construction — one primitive owns the merge semantics.
///
/// # Attribution semantics
///
/// - **Leaf overwrite** — a later layer writing a leaf at the same
///   path replaces the prior attribution.
/// - **Dict-over-scalar** / **scalar-over-dict** — the wholesale
///   replace that [`deep_merge`] performs at cross-shape boundaries
///   purges any prior sub-leaf attribution at the replaced path and
///   re-attributes every new leaf under it to the writing layer.
/// - **Empty layer** — a layer emitting an empty [`Dict`] contributes
///   no attributions; the earlier stack is preserved verbatim.
/// - **Sibling keys** — two layers that touch different leaves under
///   the same subtree each keep credit for what they wrote (the
///   recursive dict-merge stays granular per leaf).
#[must_use]
pub fn compose_with_provenance(layers: &[&dyn DiscoveryLayer]) -> DiscoveryComposition {
    let mut dict = Dict::new();
    let mut attribution: BTreeMap<Vec<String>, &'static str> = BTreeMap::new();
    for layer in layers {
        deep_merge_attributed(
            &mut dict,
            layer.discover(),
            &[],
            layer.name(),
            &mut attribution,
        );
    }
    DiscoveryComposition {
        dict,
        attribution: LayerAttribution { inner: attribution },
    }
}

/// Deep-merge helper that mirrors [`deep_merge`] while threading
/// per-leaf attribution. Kept private: the public seam is
/// [`compose_with_provenance`], which owns the `prefix` / `layer` /
/// `attribution` protocol.
fn deep_merge_attributed(
    base: &mut Dict,
    overlay: Dict,
    prefix: &[String],
    layer: &'static str,
    attribution: &mut BTreeMap<Vec<String>, &'static str>,
) {
    for (key, incoming) in overlay {
        let mut path = Vec::with_capacity(prefix.len() + 1);
        path.extend_from_slice(prefix);
        path.push(key.clone());
        match (base.get_mut(&key), incoming) {
            // Two maps: recurse so sibling keys keep their prior
            // attribution.
            (Some(Value::Dict(_, base_inner)), Value::Dict(_, over_inner)) => {
                deep_merge_attributed(base_inner, over_inner, &path, layer, attribution);
            }
            // Anything else: wholesale replace. Any prior sub-leaves
            // under this path are gone from the merged dict, so their
            // attribution goes with them; then re-attribute the new
            // value's leaves before installing.
            (_, incoming) => {
                attribution.retain(|p, _| !path_has_prefix(p, &path));
                attribute_leaves(&incoming, &path, layer, attribution);
                base.insert(key, incoming);
            }
        }
    }
}

/// True iff `path` names a descendant of (or equals) `prefix` in the
/// dotted-path lattice.
fn path_has_prefix(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

/// Record `layer` as the writer of every leaf reachable from `path`
/// inside `v`. Recurses into [`Value::Dict`]; every other variant is a
/// leaf that gets attributed at `path` itself.
fn attribute_leaves(
    v: &Value,
    path: &[String],
    layer: &'static str,
    attribution: &mut BTreeMap<Vec<String>, &'static str>,
) {
    match v {
        Value::Dict(_, inner) => {
            for (k, sub) in inner {
                let mut sub_path = path.to_vec();
                sub_path.push(k.clone());
                attribute_leaves(sub, &sub_path, layer, attribution);
            }
        }
        _ => {
            attribution.insert(path.to_vec(), layer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::value::Value;

    /// A test layer that emits a fixed dict under a fixed name.
    struct Fixed(&'static str, Dict);
    impl DiscoveryLayer for Fixed {
        fn name(&self) -> &'static str {
            self.0
        }
        fn discover(&self) -> Dict {
            self.1.clone()
        }
    }

    fn dict(pairs: &[(&str, Value)]) -> Dict {
        let mut d = Dict::new();
        for (k, v) in pairs {
            d.insert((*k).to_owned(), v.clone());
        }
        d
    }

    #[test]
    fn deep_merge_overlay_wins_scalars_and_keeps_siblings() {
        let mut base = dict(&[("a", Value::from(1i64)), ("b", Value::from(2i64))]);
        deep_merge(
            &mut base,
            dict(&[("b", Value::from(20i64)), ("c", Value::from(3i64))]),
        );
        assert_eq!(
            base.get("a"),
            Some(&Value::from(1i64)),
            "untouched sibling kept"
        );
        assert_eq!(base.get("b"), Some(&Value::from(20i64)), "overlay wins");
        assert_eq!(base.get("c"), Some(&Value::from(3i64)), "new key added");
    }

    #[test]
    fn deep_merge_recurses_into_nested_dicts() {
        let mut base = dict(&[(
            "breathe",
            Value::from(dict(&[
                ("setpoint", Value::from(0.80)),
                ("mode", Value::from("live")),
            ])),
        )]);
        // Overlay only changes mode; setpoint must survive the nested merge.
        deep_merge(
            &mut base,
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let Some(Value::Dict(_, inner)) = base.get("breathe") else {
            panic!("nested dict preserved");
        };
        assert_eq!(
            inner.get("setpoint"),
            Some(&Value::from(0.80)),
            "sibling survives"
        );
        assert_eq!(
            inner.get("mode"),
            Some(&Value::from("shadow")),
            "leaf overridden"
        );
    }

    #[test]
    fn deep_merge_dict_replaces_scalar_and_vice_versa() {
        // scalar base, dict overlay → overlay replaces (not a type-confused merge).
        let mut base = dict(&[("x", Value::from(1i64))]);
        deep_merge(
            &mut base,
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        assert!(
            matches!(base.get("x"), Some(Value::Dict(..))),
            "dict replaced scalar"
        );

        // dict base, scalar overlay → overlay replaces (the reverse direction).
        let mut base = dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]);
        deep_merge(&mut base, dict(&[("x", Value::from(9i64))]));
        assert_eq!(
            base.get("x"),
            Some(&Value::from(9i64)),
            "scalar replaced dict"
        );
    }

    #[test]
    fn deep_merge_replaces_arrays_wholesale() {
        // Arrays REPLACE (matching figment's Order::Merge); they are not
        // concatenated. A discovered list-valued key (e.g. an ingress list) from
        // a specific layer fully supersedes a coarser one.
        let mut base = dict(&[(
            "xs",
            Value::from(vec![Value::from(1i64), Value::from(2i64)]),
        )]);
        deep_merge(
            &mut base,
            dict(&[("xs", Value::from(vec![Value::from(9i64)]))]),
        );
        let Some(Value::Array(_, arr)) = base.get("xs") else {
            panic!("array value");
        };
        assert_eq!(arr.len(), 1, "array replaced wholesale, not concatenated");
        assert_eq!(arr[0], Value::from(9i64));
    }

    #[test]
    fn deep_merge_recurses_three_levels_preserving_each_sibling() {
        let mut base = dict(&[(
            "a",
            Value::from(dict(&[(
                "b",
                Value::from(dict(&[
                    ("keep", Value::from(1i64)),
                    ("change", Value::from(2i64)),
                ])),
            )])),
        )]);
        deep_merge(
            &mut base,
            dict(&[(
                "a",
                Value::from(dict(&[(
                    "b",
                    Value::from(dict(&[("change", Value::from(20i64))])),
                )])),
            )]),
        );
        let Some(Value::Dict(_, a)) = base.get("a") else {
            panic!("a")
        };
        let Some(Value::Dict(_, b)) = a.get("b") else {
            panic!("b")
        };
        assert_eq!(
            b.get("keep"),
            Some(&Value::from(1i64)),
            "level-3 sibling survives"
        );
        assert_eq!(
            b.get("change"),
            Some(&Value::from(20i64)),
            "level-3 leaf overridden"
        );
    }

    #[test]
    fn compose_specific_layer_overrides_coarse() {
        let coarse = Fixed(
            "platform",
            dict(&[
                ("setpoint", Value::from(0.80)),
                ("floor", Value::from("256Mi")),
            ]),
        );
        let specific = Fixed("tenancy", dict(&[("setpoint", Value::from(0.70))]));
        let out = compose(&[&coarse, &specific]);
        assert_eq!(
            out.get("setpoint"),
            Some(&Value::from(0.70)),
            "specific (later) wins"
        );
        assert_eq!(
            out.get("floor"),
            Some(&Value::from("256Mi")),
            "coarse-only key retained"
        );
    }

    #[test]
    fn compose_empty_layer_contributes_nothing() {
        let real = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        assert_eq!(
            compose(&[&real, &empty]),
            compose(&[&real]),
            "empty axis invisible"
        );
    }

    #[test]
    fn compose_no_layers_is_empty() {
        assert!(compose(&[]).is_empty());
    }

    #[test]
    fn layer_names_in_application_order() {
        let a = Fixed("platform", Dict::new());
        let b = Fixed("tenancy", Dict::new());
        assert_eq!(layer_names(&[&a, &b]), vec!["platform", "tenancy"]);
    }

    // -------- compose_with_provenance --------

    #[test]
    fn compose_with_provenance_attributes_each_leaf_to_its_writer() {
        let a = Fixed(
            "platform",
            dict(&[("k1", Value::from(1i64)), ("k2", Value::from(2i64))]),
        );
        let b = Fixed(
            "tenancy",
            dict(&[("k2", Value::from(20i64)), ("k3", Value::from(3i64))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.dict,
            compose(&[&a, &b]),
            "dict projection agrees with compose"
        );
        assert_eq!(out.attribution.layer_of(&["k1"]), Some("platform"));
        assert_eq!(
            out.attribution.layer_of(&["k2"]),
            Some("tenancy"),
            "later layer wins per leaf"
        );
        assert_eq!(out.attribution.layer_of(&["k3"]), Some("tenancy"));
        assert_eq!(
            out.attribution.layer_of(&["never"]),
            None,
            "unset paths are unattributed"
        );
        assert_eq!(out.attribution.len(), 3);
        assert!(!out.attribution.is_empty());
    }

    #[test]
    fn compose_with_provenance_recurses_into_nested_dicts_per_leaf() {
        let a = Fixed(
            "platform",
            dict(&[(
                "breathe",
                Value::from(dict(&[
                    ("setpoint", Value::from(0.80)),
                    ("mode", Value::from("live")),
                ])),
            )]),
        );
        // Overlay only touches `breathe.mode`; the sibling `breathe.setpoint`
        // stays attributed to the coarse layer.
        let b = Fixed(
            "tenancy",
            dict(&[(
                "breathe",
                Value::from(dict(&[("mode", Value::from("shadow"))])),
            )]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["breathe", "setpoint"]),
            Some("platform"),
            "sibling under nested dict retains coarse writer"
        );
        assert_eq!(
            out.attribution.layer_of(&["breathe", "mode"]),
            Some("tenancy"),
            "overwritten nested leaf gets the specific writer"
        );
        assert_eq!(out.attribution.len(), 2);
    }

    #[test]
    fn compose_with_provenance_dict_replaces_scalar_purges_prior_attribution() {
        // Layer A writes a scalar at `x`; layer B replaces it with a dict.
        // The prior `x` leaf attribution is purged (there's no `x` leaf
        // anymore — `x` is now a dict node), and the new `x.y` leaf is
        // attributed to B.
        let a = Fixed("first", dict(&[("x", Value::from(1i64))]));
        let b = Fixed(
            "second",
            dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["x"]),
            None,
            "scalar leaf attribution purged when replaced by a dict"
        );
        assert_eq!(out.attribution.layer_of(&["x", "y"]), Some("second"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_scalar_replaces_dict_purges_sub_attributions() {
        // Layer A writes a dict subtree; layer B replaces it wholesale
        // with a scalar. Every sub-leaf attribution under `x` is purged,
        // and the new leaf at `x` is attributed to B.
        let a = Fixed(
            "first",
            dict(&[(
                "x",
                Value::from(dict(&[("y", Value::from(1i64)), ("z", Value::from(2i64))])),
            )]),
        );
        let b = Fixed("second", dict(&[("x", Value::from(99i64))]));
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(
            out.attribution.layer_of(&["x", "y"]),
            None,
            "sub-leaf attribution purged when parent replaced by scalar"
        );
        assert_eq!(out.attribution.layer_of(&["x", "z"]), None);
        assert_eq!(
            out.attribution.layer_of(&["x"]),
            Some("second"),
            "replacing scalar attributed at the flattened path"
        );
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_arrays_replace_wholesale_and_reattribute() {
        // Matches deep_merge's array-replace-wholesale semantics: the
        // whole array leaf is credited to the later writer.
        let a = Fixed(
            "first",
            dict(&[("xs", Value::from(vec![Value::from(1i64)]))]),
        );
        let b = Fixed(
            "second",
            dict(&[(
                "xs",
                Value::from(vec![Value::from(9i64), Value::from(10i64)]),
            )]),
        );
        let out = compose_with_provenance(&[&a, &b]);
        assert_eq!(out.attribution.layer_of(&["xs"]), Some("second"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_empty_layer_preserves_prior_attribution() {
        // An undetectable axis contributes nothing — the earlier stack
        // is preserved verbatim, including attribution.
        let a = Fixed("real", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        let out = compose_with_provenance(&[&a, &empty]);
        assert_eq!(out.attribution.layer_of(&["k"]), Some("real"));
        assert_eq!(out.attribution.len(), 1);
    }

    #[test]
    fn compose_with_provenance_no_layers_is_empty_and_unattributed() {
        let out = compose_with_provenance(&[]);
        assert!(out.dict.is_empty());
        assert!(out.attribution.is_empty());
        assert_eq!(out.attribution.len(), 0);
    }

    #[test]
    fn compose_with_provenance_iter_yields_lexicographic_order() {
        // BTreeMap keyed on Vec<String> sorts lex on the whole vector:
        // ["a","y"] < ["m"] < ["z"] (element-wise ordering; shorter
        // prefixes come first only when the compared elements tie).
        let a = Fixed("A", dict(&[("z", Value::from(1i64))]));
        let b = Fixed(
            "B",
            dict(&[("a", Value::from(dict(&[("y", Value::from(2i64))])))]),
        );
        let c = Fixed("C", dict(&[("m", Value::from(3i64))]));
        let out = compose_with_provenance(&[&a, &b, &c]);
        let observed: Vec<(Vec<String>, &'static str)> = out
            .attribution
            .iter()
            .map(|(p, l)| (p.to_vec(), l))
            .collect();
        assert_eq!(
            observed,
            vec![
                (vec!["a".to_owned(), "y".to_owned()], "B"),
                (vec!["m".to_owned()], "C"),
                (vec!["z".to_owned()], "A"),
            ]
        );
    }

    #[test]
    fn compose_with_provenance_dict_matches_independent_deep_merge_walk() {
        // `compose` now routes through `compose_with_provenance` (one
        // primitive owns the merge semantics), so comparing
        // `out.dict == compose(layers)` alone would be tautological.
        // This test walks the layers through the standalone
        // [`deep_merge`] primitive as an independent reference —
        // pinning the attributed primitive's dict against a merge
        // implementation that carries none of its state.
        let a = Fixed(
            "A",
            dict(&[
                ("outer", Value::from(dict(&[("a", Value::from(1i64))]))),
                ("scalar", Value::from(1i64)),
            ]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("outer", Value::from(dict(&[("b", Value::from(2i64))]))),
                // Cross-shape: overwrites scalar with dict.
                ("scalar", Value::from(dict(&[("inner", Value::from(9i64))]))),
            ]),
        );
        let via_prov = compose_with_provenance(&[&a, &b]).dict;
        let mut via_plain = Dict::new();
        deep_merge(&mut via_plain, a.discover());
        deep_merge(&mut via_plain, b.discover());
        assert_eq!(
            via_prov, via_plain,
            "attributed compose dict matches independent deep_merge walk"
        );
    }

    #[test]
    fn compose_with_provenance_dict_matches_compose_projection_across_shape_transitions() {
        // Invariant: compose_with_provenance(...).dict == compose(...) for
        // every input — pins the "one primitive owns the merge semantics"
        // property across scalars, nested dicts, arrays, and cross-shape
        // replacement.
        let a = Fixed(
            "A",
            dict(&[
                ("scalar", Value::from(1i64)),
                (
                    "nested",
                    Value::from(dict(&[
                        ("keep", Value::from("k")),
                        ("change", Value::from("A")),
                    ])),
                ),
            ]),
        );
        let b = Fixed(
            "B",
            dict(&[
                ("nested", Value::from(dict(&[("change", Value::from("B"))]))),
                ("array", Value::from(vec![Value::from(1i64)])),
                // Cross-shape: overwrite scalar with dict.
                ("scalar", Value::from(dict(&[("inner", Value::from(2i64))]))),
            ]),
        );
        let c = Fixed(
            "C",
            dict(&[
                ("array", Value::from(vec![Value::from(9i64)])),
                // Cross-shape: overwrite dict with scalar.
                ("scalar", Value::from(99i64)),
            ]),
        );
        let out = compose_with_provenance(&[&a, &b, &c]);
        assert_eq!(
            out.dict,
            compose(&[&a, &b, &c]),
            "dict projection equals plain compose across shape transitions"
        );
        // Spot-check attribution follows the same replacements.
        assert_eq!(out.attribution.layer_of(&["nested", "keep"]), Some("A"));
        assert_eq!(out.attribution.layer_of(&["nested", "change"]), Some("B"));
        assert_eq!(out.attribution.layer_of(&["array"]), Some("C"));
        assert_eq!(out.attribution.layer_of(&["scalar"]), Some("C"));
        // The intermediate B-written `scalar.inner` sub-leaf is purged by C.
        assert_eq!(out.attribution.layer_of(&["scalar", "inner"]), None);
    }
}
