use figment::providers::Format;
use serde::de::DeserializeOwned;

pub struct Yaml;

impl Format for Yaml {
    type Error = serde_norway::Error;

    const NAME: &'static str = "YAML";

    fn from_str<T: DeserializeOwned>(s: &str) -> Result<T, Self::Error> {
        serde_norway::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::Yaml;
    use figment::Figment;
    use figment::providers::Format;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Cfg {
        name: String,
        port: u16,
        tags: Vec<String>,
    }

    #[test]
    fn it_reads_yaml_the_way_figments_own_provider_did() {
        let cfg: Cfg = Figment::new()
            .merge(Yaml::string("name: shikumi\nport: 8080\ntags: [a, b]\n"))
            .extract()
            .unwrap();
        assert_eq!(
            cfg,
            Cfg {
                name: "shikumi".into(),
                port: 8080,
                tags: vec!["a".into(), "b".into()],
            }
        );
    }

    #[test]
    fn its_metadata_keeps_the_yaml_name() {
        let figment = Figment::new().merge(Yaml::string("a: 1\n"));
        let md = figment.find_metadata("a").unwrap();
        assert!(md.name.contains("YAML"), "{}", md.name);
    }

    #[test]
    fn the_unmaintained_libyaml_never_returns_to_the_lock() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
            .expect("shikumi commits its Cargo.lock");
        assert!(
            !lock.contains("name = \"unsafe-libyaml\"\n"),
            "unsafe-libyaml (RUSTSEC-2024-0449) is back in Cargo.lock: figment's `yaml` feature or serde_yaml was re-added"
        );
        assert!(lock.contains("name = \"unsafe-libyaml-norway\"\n"));
    }

    #[test]
    fn malformed_yaml_is_an_error_not_an_empty_config() {
        let r: Result<Cfg, _> = Figment::new()
            .merge(Yaml::string("name: [unclosed\n"))
            .extract();
        assert!(r.is_err());
    }
}
