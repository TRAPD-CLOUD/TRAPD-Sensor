//! Die Beispielkonfiguration muss zur Codebasis passen.
//!
//! `SensorConfig` ist mit `deny_unknown_fields` deklariert: sobald ein Feld
//! umbenannt oder entfernt wird, schlaegt dieser Test fehl statt dass Nutzer
//! spaeter ueber eine Datei stolpern, die der Sensor nicht mehr liest.

use std::path::PathBuf;

use trapd_sensor_core::config::{SensorConfig, SensorMode};

fn example_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/config.example.toml")
}

#[test]
fn the_shipped_example_config_parses_and_validates() {
    let path = example_path();
    let config = SensorConfig::load(&path)
        .unwrap_or_else(|e| panic!("packaging/config.example.toml does not load: {e}"));

    assert_eq!(config.sensor.mode, SensorMode::Balanced);
    assert!(config.validate().is_ok());
}

/// Die ausgelieferte Vorlage darf niemanden versehentlich scannen lassen.
#[test]
fn the_shipped_example_does_not_enable_active_discovery() {
    let config = SensorConfig::load(&example_path()).expect("example config");
    let policy = config.effective_policy();

    assert!(
        policy.active.is_none(),
        "the example must ship with active discovery off"
    );
    assert!(!config.active.enabled);
    assert!(!config.active.acknowledged);
    assert!(!config.active.snmp.enabled);
    assert!(config.active.snmp.communities.is_empty());
}

#[test]
fn the_shipped_example_keeps_auto_update_off() {
    let config = SensorConfig::load(&example_path()).expect("example config");
    assert!(
        !config.update.auto_update,
        "unattended updates on a security-critical sensor are an opt-in"
    );
}
