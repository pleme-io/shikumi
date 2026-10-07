//! Config-schema emission — one source of truth for generated config surfaces.
//!
//! A shikumi-typed config is a serde struct with a `Default`. Everything a
//! downstream generator needs to reproduce its surface — a nix HM option tree,
//! a YAML defaults file — is already in the Rust type: the field names and
//! kinds from its [`schemars`] schema, the actual default VALUES from
//! `T::default()`. [`emit`] joins the two into the flat, typed description the
//! pleme-io nix layer already consumes as `shikumiTypedGroups`, so the Rust
//! config and its nix/yaml surfaces are 1:1 BY CONSTRUCTION rather than
//! hand-mirrored — the drift class that silently rendered a fleet's
//! `tear.auto_attach` absent (mado, 2026-10-07) becomes unrepresentable.
//!
//! The output shape, per top-level group → leaf field, matches the hand-written
//! groups verbatim so migration is byte-parity-checkable:
//!
//! ```json
//! { "cursor": { "style": { "type": "enum", "values": ["block","bar"],
//!                          "default": "block", "description": "Cursor style." },
//!               "blink": { "type": "bool", "default": true, "description": "…" } } }
//! ```
//!
//! WHY the schema AND the default value, not one alone: `schemars` knows a
//! field's type, enum variants and doc comment but NOT a serde `default = "fn"`
//! value (the function is opaque to it); `T::default()` knows the values but not
//! the enum variants or docs. The generator needs both, so [`emit`] merges them.

use serde_json::{Map, Value};

/// Build the typed group description for a config type `T` — its [`schemars`]
/// schema (types, enum variants, docs) merged with the VALUES from
/// `T::default()`. The result is a JSON object of `group → field → {type,
/// default, description, values?}`, the exact shape the nix layer reads.
///
/// `T` must be `Default + Serialize` (for the values) and `JsonSchema` (for the
/// types). Returns the normalized groups object.
pub fn emit<T>() -> Value
where
    T: Default + serde::Serialize + schemars::JsonSchema,
{
    let schema = schemars::schema_for!(T).to_value();
    let default = serde_json::to_value(T::default()).unwrap_or(Value::Null);
    normalize(&schema, &default)
}

/// PURE core: walk a schemars root schema + a serialized default value into the
/// `group → field → {type, default, description, values?}` groups object. No
/// `schemars`, no I/O — so every type-mapping and merge rule is unit-testable
/// against hand-built JSON, independent of any real deriving type.
pub fn normalize(schema: &Value, default: &Value) -> Value {
    let defs = schema.get("$defs").and_then(Value::as_object);
    let mut groups = Map::new();

    if let Some(props) = schema.get("properties").and_then(Value::as_object) {
        for (gname, graw) in props {
            let gschema = resolve(graw, defs);
            let gdefault = default.get(gname).unwrap_or(&Value::Null);
            if let Some(fields) = gschema.get("properties").and_then(Value::as_object) {
                let mut out = Map::new();
                for (fname, fraw) in fields {
                    let fschema = resolve(fraw, defs);
                    // The description can sit on the reference site OR the
                    // resolved target; prefer the site (it is the field's own
                    // doc, not the shared type's).
                    let desc = string_at(fraw, "description")
                        .or_else(|| string_at(&fschema, "description"))
                        .unwrap_or_default();
                    out.insert(
                        fname.clone(),
                        field_entry(&fschema, gdefault.get(fname), desc),
                    );
                }
                groups.insert(gname.clone(), Value::Object(out));
            }
        }
    }
    Value::Object(groups)
}

/// Follow a single `$ref` into `$defs`; a schema that is not a bare reference is
/// returned as-is. One hop is enough for the struct-of-groups shape serde emits.
fn resolve(node: &Value, defs: Option<&Map<String, Value>>) -> Value {
    if let (Some(r), Some(defs)) = (string_at(node, "$ref"), defs) {
        if let Some(name) = r.strip_prefix("#/$defs/") {
            if let Some(target) = defs.get(name) {
                return target.clone();
            }
        }
    }
    node.clone()
}

/// Build one field's `{type, default, description, values?}` entry.
fn field_entry(schema: &Value, default: Option<&Value>, description: String) -> Value {
    let (ty, values) = map_type(schema);
    let mut e = Map::new();
    e.insert("type".into(), Value::String(ty));
    if let Some(vals) = values {
        e.insert("values".into(), Value::Array(vals));
    }
    e.insert("default".into(), default.cloned().unwrap_or(Value::Null));
    e.insert("description".into(), Value::String(description));
    Value::Object(e)
}

/// Map a resolved leaf schema to a shikumi group type string, plus enum values
/// when it is an enum. Mirrors the vocabulary the hand-written groups use:
/// `bool` / `int` / `float` / `str` / `enum` / `nullOrStr`.
fn map_type(schema: &Value) -> (String, Option<Vec<Value>>) {
    // Enum of string literals → "enum" + its values.
    if let Some(vals) = schema.get("enum").and_then(Value::as_array) {
        if vals.iter().all(Value::is_string) {
            return ("enum".into(), Some(vals.clone()));
        }
    }
    // `Option<T>` renders as a type array `["<t>","null"]` or an `anyOf` with a
    // null branch. Only the string case has a dedicated nix type today.
    if is_nullable_of(schema, "string") {
        return ("nullOrStr".into(), None);
    }
    match type_name(schema).as_deref() {
        Some("boolean") => ("bool".into(), None),
        Some("integer") => ("int".into(), None),
        Some("number") => ("float".into(), None),
        Some("string") => ("str".into(), None),
        // Unknown / composite (nested object, list) — surfaced verbatim so the
        // generator can decide; it is never silently coerced to a scalar.
        other => (other.unwrap_or("unknown").into(), None),
    }
}

/// The scalar type name, whether `"type": "string"` or `"type": ["string",
/// "null"]` (the non-null member wins).
fn type_name(schema: &Value) -> Option<String> {
    match schema.get("type") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .find(|s| *s != "null")
            .map(str::to_string),
        _ => None,
    }
}

/// True when the schema is `T | null` for the given `T` — either a `["T",
/// "null"]` type array or an `anyOf`/`oneOf` with a null branch and a `T` branch.
fn is_nullable_of(schema: &Value, t: &str) -> bool {
    if let Some(Value::Array(a)) = schema.get("type") {
        let strs: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
        return strs.contains(&"null") && strs.contains(&t);
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = schema.get(key) {
            let has_null = branches
                .iter()
                .any(|b| type_name(b).as_deref() == Some("null"));
            let has_t = branches.iter().any(|b| type_name(b).as_deref() == Some(t));
            if has_null && has_t {
                return true;
            }
        }
    }
    false
}

fn string_at(node: &Value, key: &str) -> Option<String> {
    node.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A schemars-1.x-shaped root: groups reference struct defs; leaf fields
    // carry `type` / `enum` / `description`; Option<String> is a null type-union.
    fn sample_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "cursor": { "$ref": "#/$defs/CursorConfig" },
                "tear": { "$ref": "#/$defs/TearConfig" }
            },
            "$defs": {
                "CursorConfig": {
                    "type": "object",
                    "properties": {
                        "style": { "enum": ["block", "bar", "underline"], "description": "Cursor style." },
                        "blink_rate_ms": { "type": "integer", "description": "Blink rate." }
                    }
                },
                "TearConfig": {
                    "type": "object",
                    "properties": {
                        "mode": { "enum": ["auto", "always", "never", "attach"], "description": "Tear attachment policy." },
                        "auto_spawn": { "type": "boolean", "description": "Spawn on demand." },
                        "socket": { "type": ["string", "null"], "description": "Daemon socket path." }
                    }
                }
            }
        })
    }

    fn sample_default() -> Value {
        json!({
            "cursor": { "style": "block", "blink_rate_ms": 500 },
            "tear": { "mode": "auto", "auto_spawn": true, "socket": null }
        })
    }

    #[test]
    fn enum_field_carries_type_values_default_and_doc() {
        let groups = normalize(&sample_schema(), &sample_default());
        let style = &groups["cursor"]["style"];
        assert_eq!(style["type"], json!("enum"));
        assert_eq!(style["values"], json!(["block", "bar", "underline"]));
        assert_eq!(style["default"], json!("block"));
        assert_eq!(style["description"], json!("Cursor style."));
    }

    #[test]
    fn scalar_types_map_to_the_shikumi_vocabulary() {
        let groups = normalize(&sample_schema(), &sample_default());
        assert_eq!(groups["cursor"]["blink_rate_ms"]["type"], json!("int"));
        assert_eq!(groups["cursor"]["blink_rate_ms"]["default"], json!(500));
        assert_eq!(groups["tear"]["auto_spawn"]["type"], json!("bool"));
        assert_eq!(groups["tear"]["auto_spawn"]["default"], json!(true));
    }

    #[test]
    fn tear_mode_is_the_regression_this_exists_for() {
        // The exact field whose hand-mirrored default drifted. Generated, its
        // type, variants and default all come straight from the Rust type.
        let groups = normalize(&sample_schema(), &sample_default());
        let mode = &groups["tear"]["mode"];
        assert_eq!(mode["type"], json!("enum"));
        assert_eq!(mode["values"], json!(["auto", "always", "never", "attach"]));
        assert_eq!(mode["default"], json!("auto"));
    }

    #[test]
    fn optional_string_becomes_null_or_str_and_keeps_its_null_default() {
        let groups = normalize(&sample_schema(), &sample_default());
        assert_eq!(groups["tear"]["socket"]["type"], json!("nullOrStr"));
        assert_eq!(groups["tear"]["socket"]["default"], json!(null));
    }

    #[test]
    fn anyof_nullable_string_also_maps_to_null_or_str() {
        // schemars sometimes emits Option<String> as an anyOf rather than a
        // type array; both must land on the same nix type.
        let schema = json!({
            "type": "object",
            "properties": { "g": { "$ref": "#/$defs/G" } },
            "$defs": { "G": { "type": "object", "properties": {
                "name": { "anyOf": [ { "type": "string" }, { "type": "null" } ] }
            } } }
        });
        let default = json!({ "g": { "name": null } });
        let groups = normalize(&schema, &default);
        assert_eq!(groups["g"]["name"]["type"], json!("nullOrStr"));
    }

    #[test]
    fn description_prefers_the_reference_site_over_the_shared_target() {
        // A field doc on the $ref site must win over the referenced type's own
        // doc — the field's meaning, not the shared struct's.
        let schema = json!({
            "type": "object",
            "properties": { "g": { "$ref": "#/$defs/G" } },
            "$defs": {
                "G": { "type": "object", "properties": {
                    "n": { "$ref": "#/$defs/N", "description": "field-site doc" }
                } },
                "N": { "type": "integer", "description": "shared-type doc" }
            }
        });
        let default = json!({ "g": { "n": 1 } });
        let groups = normalize(&schema, &default);
        assert_eq!(groups["g"]["n"]["description"], json!("field-site doc"));
        assert_eq!(groups["g"]["n"]["type"], json!("int"));
    }
}
