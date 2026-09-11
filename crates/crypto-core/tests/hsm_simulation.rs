//! Application simulation/policy tests, NOT PKCS#11 or hardware integration.
use crypto_core::hsm::{create_hsm_session, HsmConfig, HsmType};
use std::process::Command;

fn config(hsm_type: HsmType) -> HsmConfig {
    HsmConfig {
        hsm_type,
        connection: "in-memory-test".into(),
        slot: 0,
        key_label_prefix: "release-test".into(),
    }
}

#[test]
fn unimplemented_hardware_backends_fail_closed() {
    for backend in [
        HsmType::ThalesLuna,
        HsmType::Utimaco,
        HsmType::AwsCloudHsm,
        HsmType::AzureKeyVault,
    ] {
        assert!(create_hsm_session(&config(backend)).is_err());
    }
}

#[test]
fn simulation_policy_subprocess() {
    let Ok(case) = std::env::var("RSRP_HSM_TEST_CASE") else {
        return;
    };
    let session = create_hsm_session(&config(HsmType::SoftHSM));
    if case != "allowed" {
        assert!(session.is_err(), "simulation must fail closed: {case}");
        return;
    }
    let mut session = session.unwrap();
    let key = session.generate_key_pair("ED25519", "release-key").unwrap();
    let signature = session.sign(&key, b"release evidence").unwrap();
    assert!(session
        .verify(&key, b"release evidence", &signature)
        .unwrap());
    assert!(!session.verify(&key, b"tampered", &signature).unwrap());
    assert!(!session
        .verify(&key, b"release evidence", &signature[..63])
        .unwrap());
    let other = session.generate_key_pair("ED25519", "other-key").unwrap();
    assert!(!session
        .verify(&other, b"release evidence", &signature)
        .unwrap());
    assert!(session.import_key("bad-seed", &[0; 31]).is_err());
    session.close();
    assert!(session.sign(&key, b"release evidence").is_err());
    assert!(session
        .verify(&key, b"release evidence", &signature)
        .is_err());
}

#[test]
fn simulation_requires_opt_in_and_is_forbidden_in_production() {
    // Child processes isolate environment settings from the parallel test harness.
    for case in [
        "disabled",
        "allowed",
        "ENV",
        "APP_ENV",
        "RUST_ENV",
        "RSRP_DEPLOYMENT_PROFILE",
    ] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child.args(["--exact", "simulation_policy_subprocess", "--nocapture"]);
        for name in [
            "ENV",
            "APP_ENV",
            "RUST_ENV",
            "RSRP_DEPLOYMENT_PROFILE",
            "RSRP_ALLOW_SOFT_HSM",
        ] {
            child.env_remove(name);
        }
        child.env("RSRP_HSM_TEST_CASE", case);
        if case != "disabled" {
            child.env("RSRP_ALLOW_SOFT_HSM", "1");
        }
        if case != "disabled" && case != "allowed" {
            child.env(case, "production");
        }
        assert!(child.status().unwrap().success(), "HSM policy case: {case}");
    }
}
