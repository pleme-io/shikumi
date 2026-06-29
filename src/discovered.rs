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
#[must_use]
pub fn compose(layers: &[&dyn DiscoveryLayer]) -> Dict {
    let mut acc = Dict::new();
    for layer in layers {
        deep_merge(&mut acc, layer.discover());
    }
    acc
}

/// The provenance names of an ordered layer stack, in application order.
#[must_use]
pub fn layer_names(layers: &[&dyn DiscoveryLayer]) -> Vec<&'static str> {
    layers.iter().map(|layer| layer.name()).collect()
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
        deep_merge(&mut base, dict(&[("b", Value::from(20i64)), ("c", Value::from(3i64))]));
        assert_eq!(base.get("a"), Some(&Value::from(1i64)), "untouched sibling kept");
        assert_eq!(base.get("b"), Some(&Value::from(20i64)), "overlay wins");
        assert_eq!(base.get("c"), Some(&Value::from(3i64)), "new key added");
    }

    #[test]
    fn deep_merge_recurses_into_nested_dicts() {
        let mut base = dict(&[(
            "breathe",
            Value::from(dict(&[("setpoint", Value::from(0.80)), ("mode", Value::from("live"))])),
        )]);
        // Overlay only changes mode; setpoint must survive the nested merge.
        deep_merge(
            &mut base,
            dict(&[("breathe", Value::from(dict(&[("mode", Value::from("shadow"))])))]),
        );
        let Some(Value::Dict(_, inner)) = base.get("breathe") else {
            panic!("nested dict preserved");
        };
        assert_eq!(inner.get("setpoint"), Some(&Value::from(0.80)), "sibling survives");
        assert_eq!(inner.get("mode"), Some(&Value::from("shadow")), "leaf overridden");
    }

    #[test]
    fn deep_merge_dict_replaces_scalar_and_vice_versa() {
        // scalar base, dict overlay → overlay replaces (not a type-confused merge).
        let mut base = dict(&[("x", Value::from(1i64))]);
        deep_merge(&mut base, dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]));
        assert!(matches!(base.get("x"), Some(Value::Dict(..))), "dict replaced scalar");

        // dict base, scalar overlay → overlay replaces (the reverse direction).
        let mut base = dict(&[("x", Value::from(dict(&[("y", Value::from(2i64))])))]);
        deep_merge(&mut base, dict(&[("x", Value::from(9i64))]));
        assert_eq!(base.get("x"), Some(&Value::from(9i64)), "scalar replaced dict");
    }

    #[test]
    fn deep_merge_replaces_arrays_wholesale() {
        // Arrays REPLACE (matching figment's Order::Merge); they are not
        // concatenated. A discovered list-valued key (e.g. an ingress list) from
        // a specific layer fully supersedes a coarser one.
        let mut base = dict(&[("xs", Value::from(vec![Value::from(1i64), Value::from(2i64)]))]);
        deep_merge(&mut base, dict(&[("xs", Value::from(vec![Value::from(9i64)]))]));
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
                Value::from(dict(&[("keep", Value::from(1i64)), ("change", Value::from(2i64))])),
            )])),
        )]);
        deep_merge(
            &mut base,
            dict(&[(
                "a",
                Value::from(dict(&[("b", Value::from(dict(&[("change", Value::from(20i64))])))])),
            )]),
        );
        let Some(Value::Dict(_, a)) = base.get("a") else { panic!("a") };
        let Some(Value::Dict(_, b)) = a.get("b") else { panic!("b") };
        assert_eq!(b.get("keep"), Some(&Value::from(1i64)), "level-3 sibling survives");
        assert_eq!(b.get("change"), Some(&Value::from(20i64)), "level-3 leaf overridden");
    }

    #[test]
    fn compose_specific_layer_overrides_coarse() {
        let coarse = Fixed("platform", dict(&[("setpoint", Value::from(0.80)), ("floor", Value::from("256Mi"))]));
        let specific = Fixed("tenancy", dict(&[("setpoint", Value::from(0.70))]));
        let out = compose(&[&coarse, &specific]);
        assert_eq!(out.get("setpoint"), Some(&Value::from(0.70)), "specific (later) wins");
        assert_eq!(out.get("floor"), Some(&Value::from("256Mi")), "coarse-only key retained");
    }

    #[test]
    fn compose_empty_layer_contributes_nothing() {
        let real = Fixed("cloud", dict(&[("k", Value::from(1i64))]));
        let empty = Fixed("undetectable", Dict::new());
        assert_eq!(compose(&[&real, &empty]), compose(&[&real]), "empty axis invisible");
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
}
