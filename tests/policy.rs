//! Browser auto-select policy in its several carriers.

use coqui_sslcontext::{AutoSelectRule, Error, NameFilter, rules_from_policy_values};

#[test]
fn parsed_policy_values_become_rules_and_malformed_ones_are_skipped() {
    let values: Vec<serde_json::Value> = [
        r#"{"pattern": "https://[*.]corp.example", "filter": {"ISSUER": {"CN": "Corp CA"}}}"#,
        r#"{"filter": {}}"#,
        r#""just a string""#,
    ]
    .iter()
    .map(|text| serde_json::from_str(text).unwrap())
    .collect();
    let rules: Vec<AutoSelectRule> = rules_from_policy_values(&values);
    assert_eq!(rules.len(), 1);
    assert!(rules[0].matches_host(Some("a.corp.example")));
    assert!(rules_from_policy_values(&[]).is_empty());
    let _ = NameFilter::Any;
}

#[cfg(feature = "system")]
mod plist {
    use coqui_sslcontext::rules_from_plist;

    use super::*;

    const MANAGED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>AutoSelectCertificateForUrls</key>
<array>
<string>{"pattern": "https://corp.example", "filter": {"ISSUER": {"CN": "Corp CA"}}}</string>
<dict><key>pattern</key><string>*</string>
<key>filter</key><dict><key>SUBJECT</key><dict><key>OU</key><string>Staff</string></dict></dict></dict>
<string>not json</string>
<integer>7</integer>
</array>
<key>Other</key><string>ignored</string>
</dict></plist>"#;

    #[test]
    fn a_managed_preferences_plist_gives_its_rules_from_strings_and_dictionaries() {
        let rules = rules_from_plist(MANAGED.as_bytes()).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].matches_host(Some("corp.example")));
        assert!(!rules[0].matches_host(Some("other.example")));
        assert!(rules[1].matches_host(None));
    }

    #[test]
    fn a_plist_without_the_policy_gives_none_and_a_non_plist_is_an_error() {
        let empty = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>A</key><string>b</string></dict></plist>"#;
        assert!(rules_from_plist(empty.as_bytes()).unwrap().is_empty());
        assert!(matches!(
            rules_from_plist(b"not a property list"),
            Err(Error::Credential(_))
        ));
    }
}
