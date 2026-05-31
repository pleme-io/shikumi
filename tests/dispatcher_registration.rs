//! Verify shikumi registers ConfigTierKind into the
//! gen-platform fleet catalog. shikumi is the TWELFTH consumer
//! class adopting the typed-dispatcher catamorphism — joins
//! gen / caixa / wasm-platform / cofre / shigoto / engenho /
//! magma / kura / pangea / tatara / hanshi.
//!
//! ConfigTierKind enumerates the four typed config tiers
//! every shikumi-backed app supports — Bare / Discovered /
//! Default / Custom. The substrate's typed shadow over
//! tiered configuration is now mechanically queryable through
//! one CLI call: `gen dispatchers --from-catalog | grep shikumi`.

use gen_platform::{TypedDispatcherTrait, catalog};
use shikumi::ConfigTierKind;

#[test]
fn config_tier_kind_registers_into_fleet_catalog() {
    let entry = catalog::by_label("shikumi.config-tier-kind")
        .expect("shikumi must register ConfigTierKind into the fleet catalog");
    assert_eq!(entry.label, "shikumi.config-tier-kind");
    assert_eq!((entry.variant_count)(), 4);
}

#[test]
fn variant_kinds_kebab() {
    let kinds = ConfigTierKind::variant_kinds();
    assert_eq!(kinds, vec!["bare", "discovered", "default", "custom"]);
}

#[test]
fn quintet_round_trip() {
    // FromStrKind adds a `FromStr` trait impl; ConfigTierKind ALSO
    // has an inherent `from_str(&str) -> Option<Self>` that
    // shadows. Use `.parse()` to dispatch via the FromStr trait.
    for variant in [
        ConfigTierKind::Bare,
        ConfigTierKind::Discovered,
        ConfigTierKind::Default,
        ConfigTierKind::Custom,
    ] {
        let k = variant.discriminant();
        let back: ConfigTierKind = k
            .parse()
            .unwrap_or_else(|_| panic!("FromStr must accept own discriminant: {k}"));
        assert_eq!(back.discriminant(), variant.discriminant());
    }
}

#[test]
fn inherent_from_str_coexists_with_derived_fromstr_trait() {
    // Pre-existing inherent ConfigTierKind::from_str returns Option;
    // the derived FromStr trait returns Result. Both work, target
    // different consumers.
    assert!(ConfigTierKind::from_str("bare").is_some()); // inherent
    let parsed: Result<ConfigTierKind, _> = "default".parse(); // trait
    assert!(parsed.is_ok());
}

#[test]
fn predicates() {
    let bare = ConfigTierKind::Bare;
    assert!(bare.is_bare());
    assert!(!bare.is_discovered());
    assert!(!bare.is_default());
    assert!(!bare.is_custom());
}

#[test]
fn display_delegates_to_discriminant() {
    assert_eq!(ConfigTierKind::Bare.to_string(), "bare");
    assert_eq!(ConfigTierKind::Default.to_string(), "default");
}

#[test]
fn const_fn_in_const_context() {
    const IS_BARE: bool = ConfigTierKind::Bare.is_bare();
    const KIND: &str = ConfigTierKind::Bare.discriminant();
    assert!(IS_BARE);
    assert_eq!(KIND, "bare");
}
