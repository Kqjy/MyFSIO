use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const ACL_METADATA_KEY: &str = "__acl__";
pub const GRANTEE_ALL_USERS: &str = "*";
pub const GRANTEE_AUTHENTICATED_USERS: &str = "authenticated";

const ACL_PERMISSION_FULL_CONTROL: &str = "FULL_CONTROL";
const ACL_PERMISSION_WRITE: &str = "WRITE";
const ACL_PERMISSION_WRITE_ACP: &str = "WRITE_ACP";
const ACL_PERMISSION_READ: &str = "READ";
const ACL_PERMISSION_READ_ACP: &str = "READ_ACP";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclGrant {
    pub grantee: String,
    pub permission: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Acl {
    pub owner: String,
    #[serde(default)]
    pub grants: Vec<AclGrant>,
}

impl Acl {
    pub fn allowed_actions(
        &self,
        principal_id: Option<&str>,
        is_authenticated: bool,
    ) -> HashSet<&'static str> {
        let mut actions = HashSet::new();
        if let Some(principal_id) = principal_id {
            if principal_id == self.owner {
                actions.extend(permission_to_actions(ACL_PERMISSION_FULL_CONTROL));
            }
        }
        for grant in &self.grants {
            let matches_grantee = grant.grantee == GRANTEE_ALL_USERS
                || (grant.grantee == GRANTEE_AUTHENTICATED_USERS && is_authenticated)
                || principal_id.is_some_and(|pid| grant.grantee == pid);
            if matches_grantee {
                actions.extend(permission_to_actions(&grant.permission));
            }
        }
        actions
    }
}

pub fn create_canned_acl(canned_acl: &str, owner: &str) -> Acl {
    let owner_grant = AclGrant {
        grantee: owner.to_string(),
        permission: ACL_PERMISSION_FULL_CONTROL.to_string(),
    };
    match canned_acl {
        "public-read" => Acl {
            owner: owner.to_string(),
            grants: vec![
                owner_grant,
                AclGrant {
                    grantee: GRANTEE_ALL_USERS.to_string(),
                    permission: ACL_PERMISSION_READ.to_string(),
                },
            ],
        },
        "public-read-write" => Acl {
            owner: owner.to_string(),
            grants: vec![
                owner_grant,
                AclGrant {
                    grantee: GRANTEE_ALL_USERS.to_string(),
                    permission: ACL_PERMISSION_READ.to_string(),
                },
                AclGrant {
                    grantee: GRANTEE_ALL_USERS.to_string(),
                    permission: ACL_PERMISSION_WRITE.to_string(),
                },
            ],
        },
        "authenticated-read" => Acl {
            owner: owner.to_string(),
            grants: vec![
                owner_grant,
                AclGrant {
                    grantee: GRANTEE_AUTHENTICATED_USERS.to_string(),
                    permission: ACL_PERMISSION_READ.to_string(),
                },
            ],
        },
        _ => Acl {
            owner: owner.to_string(),
            grants: vec![owner_grant],
        },
    }
}

pub fn acl_to_xml(acl: &Acl) -> String {
    acl_to_xml_with_lookup(acl, |id| id.to_string())
}

pub fn acl_to_xml_with_lookup<F>(acl: &Acl, mut display_name_for: F) -> String
where
    F: FnMut(&str) -> String,
{
    let owner_display = display_name_for(&acl.owner);
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>\
         <AccessControlList>",
        xml_escape(&acl.owner),
        xml_escape(&owner_display),
    );
    for grant in &acl.grants {
        xml.push_str("<Grant>");
        match grant.grantee.as_str() {
            GRANTEE_ALL_USERS => {
                xml.push_str(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                     <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                     </Grantee>",
                );
            }
            GRANTEE_AUTHENTICATED_USERS => {
                xml.push_str(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                     <URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI>\
                     </Grantee>",
                );
            }
            other => {
                let display = display_name_for(other);
                xml.push_str(&format!(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                     <ID>{}</ID><DisplayName>{}</DisplayName>\
                     </Grantee>",
                    xml_escape(other),
                    xml_escape(&display),
                ));
            }
        }
        xml.push_str(&format!(
            "<Permission>{}</Permission></Grant>",
            xml_escape(&grant.permission)
        ));
    }
    xml.push_str("</AccessControlList></AccessControlPolicy>");
    xml
}

pub fn acl_from_bucket_config(value: &Value) -> Option<Acl> {
    match value {
        Value::String(raw) => acl_from_xml(raw).or_else(|| serde_json::from_str(raw).ok()),
        Value::Object(_) => serde_json::from_value(value.clone()).ok(),
        _ => None,
    }
}

pub fn acl_from_object_metadata(metadata: &HashMap<String, String>) -> Option<Acl> {
    metadata
        .get(ACL_METADATA_KEY)
        .and_then(|raw| serde_json::from_str::<Acl>(raw).ok())
}

pub fn store_object_acl(metadata: &mut HashMap<String, String>, acl: &Acl) {
    if let Ok(serialized) = serde_json::to_string(acl) {
        metadata.insert(ACL_METADATA_KEY.to_string(), serialized);
    }
}

pub fn acl_from_xml(xml: &str) -> Option<Acl> {
    parse_acl_xml(xml, false)
}

pub fn acl_from_xml_strict(xml: &str) -> Option<Acl> {
    parse_acl_xml(xml, true)
}

fn parse_acl_xml(xml: &str, strict: bool) -> Option<Acl> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();

    if strict && root.tag_name().name() != "AccessControlPolicy" {
        return None;
    }

    if strict && !validate_unique_children(&root, &["Owner", "AccessControlList"]) {
        return None;
    }

    let owner_node = if strict {
        root.children()
            .find(|node| node.is_element() && node.tag_name().name() == "Owner")
    } else {
        doc.descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "Owner")
    };

    let acl_list_node = if strict {
        root.children()
            .find(|node| node.is_element() && node.tag_name().name() == "AccessControlList")
    } else {
        doc.descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "AccessControlList")
    };

    if strict && (owner_node.is_none() || acl_list_node.is_none()) {
        return None;
    }

    if strict {
        if let Some(node) = owner_node {
            if !validate_unique_children(&node, &["ID", "DisplayName"]) {
                return None;
            }
        }
    }

    let owner_id = owner_node.and_then(|node| {
        node.children()
            .find(|child| child.is_element() && child.tag_name().name() == "ID")
            .and_then(|child| child.text())
    });

    if strict {
        match owner_id.map(str::trim) {
            Some(id) if !id.is_empty() => {}
            _ => return None,
        }
    }

    let owner = owner_id.unwrap_or("myfsio").trim().to_string();

    if strict {
        if let Some(list) = acl_list_node {
            for child in list.children().filter(|n| n.is_element()) {
                if child.tag_name().name() != "Grant" {
                    return None;
                }
            }
        }
    }

    let grant_iter: Box<dyn Iterator<Item = roxmltree::Node>> = if strict {
        match acl_list_node {
            Some(list) => Box::new(
                list.children()
                    .filter(|node| node.is_element() && node.tag_name().name() == "Grant"),
            ),
            None => Box::new(std::iter::empty()),
        }
    } else {
        Box::new(
            doc.descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "Grant"),
        )
    };

    let mut grants = Vec::new();
    for grant in grant_iter {
        if strict && !validate_unique_children(&grant, &["Grantee", "Permission"]) {
            return None;
        }
        let permission = grant
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Permission")
            .and_then(|child| child.text())
            .unwrap_or_default()
            .trim()
            .to_string();
        if permission.is_empty() {
            if strict {
                return None;
            }
            continue;
        }
        if strict && !is_known_permission(&permission) {
            return None;
        }
        let grantee_node = grant
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Grantee");
        if strict && grantee_node.is_none() {
            return None;
        }
        if strict {
            if let Some(node) = grantee_node {
                if !validate_unique_children(&node, &["URI", "ID", "DisplayName", "EmailAddress"]) {
                    return None;
                }
                if !validate_grantee_identity(&node) {
                    return None;
                }
            }
        }
        let grantee = grantee_node
            .and_then(|node| {
                let uri = node
                    .children()
                    .find(|child| child.is_element() && child.tag_name().name() == "URI")
                    .and_then(|child| child.text())
                    .map(|text| text.trim().to_string());
                match uri.as_deref() {
                    Some("http://acs.amazonaws.com/groups/global/AllUsers") => {
                        Some(GRANTEE_ALL_USERS.to_string())
                    }
                    Some("http://acs.amazonaws.com/groups/global/AuthenticatedUsers") => {
                        Some(GRANTEE_AUTHENTICATED_USERS.to_string())
                    }
                    _ => node
                        .children()
                        .find(|child| child.is_element() && child.tag_name().name() == "ID")
                        .and_then(|child| child.text())
                        .map(|text| text.trim().to_string()),
                }
            })
            .unwrap_or_default();
        if grantee.is_empty() {
            if strict {
                return None;
            }
            continue;
        }
        grants.push(AclGrant {
            grantee,
            permission,
        });
    }

    Some(Acl { owner, grants })
}

fn validate_unique_children(node: &roxmltree::Node, allowed: &[&str]) -> bool {
    let mut seen: Vec<&str> = Vec::with_capacity(allowed.len());
    for child in node.children().filter(|n| n.is_element()) {
        let name = child.tag_name().name();
        let Some(slot) = allowed.iter().find(|a| **a == name).copied() else {
            return false;
        };
        if seen.contains(&slot) {
            return false;
        }
        seen.push(slot);
    }
    true
}

fn validate_grantee_identity(node: &roxmltree::Node) -> bool {
    const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

    let uri = node
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "URI")
        .and_then(|c| c.text())
        .map(str::trim);
    let id = node
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "ID")
        .and_then(|c| c.text())
        .map(str::trim);
    let email = node
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "EmailAddress");
    let display_name = node
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "DisplayName");

    let identifier_count = [uri.is_some(), id.is_some(), email.is_some()]
        .into_iter()
        .filter(|p| *p)
        .count();
    if identifier_count != 1 {
        return false;
    }

    let xsi_type = match node.attribute((XSI_NS, "type")) {
        Some(value) => value.trim(),
        None => return false,
    };

    match xsi_type {
        "Group" => {
            let Some(uri_value) = uri else {
                return false;
            };
            if !is_known_grantee_uri(uri_value) {
                return false;
            }
            if display_name.is_some() {
                return false;
            }
            true
        }
        "CanonicalUser" => {
            let Some(id_value) = id else {
                return false;
            };
            !id_value.is_empty()
        }
        "AmazonCustomerByEmail" => false,
        _ => false,
    }
}

fn is_known_grantee_uri(uri: &str) -> bool {
    matches!(
        uri,
        "http://acs.amazonaws.com/groups/global/AllUsers"
            | "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    )
}

fn is_known_permission(permission: &str) -> bool {
    matches!(
        permission,
        ACL_PERMISSION_FULL_CONTROL
            | ACL_PERMISSION_WRITE
            | ACL_PERMISSION_WRITE_ACP
            | ACL_PERMISSION_READ
            | ACL_PERMISSION_READ_ACP
    )
}

fn permission_to_actions(permission: &str) -> &'static [&'static str] {
    match permission {
        ACL_PERMISSION_FULL_CONTROL => &["read", "write", "delete", "list", "share"],
        ACL_PERMISSION_WRITE => &["write", "delete"],
        ACL_PERMISSION_WRITE_ACP => &["share"],
        ACL_PERMISSION_READ => &["read", "list"],
        ACL_PERMISSION_READ_ACP => &["share"],
        _ => &[],
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canned_acl_grants_public_read() {
        let acl = create_canned_acl("public-read", "owner");
        let actions = acl.allowed_actions(None, false);
        assert!(actions.contains("read"));
        assert!(actions.contains("list"));
        assert!(!actions.contains("write"));
    }

    #[test]
    fn xml_round_trip_preserves_grants() {
        let acl = create_canned_acl("authenticated-read", "owner");
        let parsed = acl_from_bucket_config(&Value::String(acl_to_xml(&acl))).unwrap();
        assert_eq!(parsed.owner, "owner");
        assert_eq!(parsed.grants.len(), 2);
        assert!(parsed
            .grants
            .iter()
            .any(|grant| grant.grantee == GRANTEE_AUTHENTICATED_USERS));
    }

    #[test]
    fn strict_rejects_wrong_root_element() {
        assert!(acl_from_xml_strict("<foo/>").is_none());
        assert!(acl_from_xml_strict(
            "<NotAcl><Owner><ID>x</ID></Owner><AccessControlList/></NotAcl>"
        )
        .is_none());
    }

    #[test]
    fn strict_rejects_missing_owner() {
        let xml = "<AccessControlPolicy><AccessControlList/></AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_missing_owner_id() {
        let xml = "<AccessControlPolicy><Owner></Owner><AccessControlList/></AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_empty_owner_id() {
        let xml = "<AccessControlPolicy><Owner><ID>   </ID></Owner><AccessControlList/></AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_missing_access_control_list() {
        let xml = "<AccessControlPolicy><Owner><ID>owner</ID></Owner></AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_malformed_xml() {
        assert!(acl_from_xml_strict("not xml").is_none());
        assert!(acl_from_xml_strict("").is_none());
    }

    #[test]
    fn strict_accepts_well_formed_acl_with_empty_grant_list() {
        let xml = "<AccessControlPolicy><Owner><ID>owner</ID></Owner><AccessControlList/></AccessControlPolicy>";
        let acl = acl_from_xml_strict(xml).expect("well-formed ACL must parse");
        assert_eq!(acl.owner, "owner");
        assert!(acl.grants.is_empty());
    }

    #[test]
    fn strict_accepts_full_acl_with_grants() {
        let xml = r#"<AccessControlPolicy>
            <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>
            <AccessControlList>
                <Grant>
                    <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
                    </Grantee>
                    <Permission>READ</Permission>
                </Grant>
            </AccessControlList>
        </AccessControlPolicy>"#;
        let acl = acl_from_xml_strict(xml).expect("well-formed ACL must parse");
        assert_eq!(acl.owner, "owner");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].grantee, GRANTEE_ALL_USERS);
        assert_eq!(acl.grants[0].permission, "READ");
    }

    #[test]
    fn lenient_still_accepts_legacy_payloads() {
        assert!(acl_from_xml("<foo/>").is_some());
        let acl = acl_from_xml("<foo/>").unwrap();
        assert_eq!(acl.owner, "myfsio");
        assert!(acl.grants.is_empty());
    }

    #[test]
    fn strict_rejects_grant_without_grantee() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Permission>READ</Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grant_without_permission() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                </Grantee></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grant_with_empty_permission() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                    <ID>u</ID></Grantee><Permission>   </Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grant_with_empty_grantee_id() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                    <ID></ID></Grantee><Permission>READ</Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_permission() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                </Grantee><Permission>NUKE</Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_first_invalid_among_otherwise_valid_grants() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                </Grantee><Permission>READ</Permission></Grant>\
                <Grant><Permission>WRITE</Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_accepts_all_known_permissions() {
        for p in ["FULL_CONTROL", "WRITE", "WRITE_ACP", "READ", "READ_ACP"] {
            let xml = format!(
                "<AccessControlPolicy>\
                <Owner><ID>owner</ID></Owner>\
                <AccessControlList>\
                    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee><Permission>{}</Permission></Grant>\
                </AccessControlList>\
                </AccessControlPolicy>",
                p
            );
            let acl = acl_from_xml_strict(&xml)
                .unwrap_or_else(|| panic!("permission {} should parse", p));
            assert_eq!(acl.grants.len(), 1);
            assert_eq!(acl.grants[0].permission, p);
        }
    }

    #[test]
    fn strict_rejects_grant_outside_access_control_list() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList/>\
            <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
            </Grantee><Permission>READ</Permission></Grant>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_sibling_grant_after_access_control_list() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                </Grantee><Permission>READ</Permission></Grant>\
            </AccessControlList>\
            <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                <ID>injected</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_top_level_element() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList/>\
            <Bogus/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_duplicate_owner() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <Owner><ID>second</ID></Owner>\
            <AccessControlList/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_duplicate_access_control_list() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList/>\
            <AccessControlList/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_owner_nested_inside_other_element() {
        let xml = "<AccessControlPolicy>\
            <Wrapper><Owner><ID>owner</ID></Owner></Wrapper>\
            <AccessControlList/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_access_control_list_nested_inside_other_element() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <Wrapper><AccessControlList/></Wrapper>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_child_in_access_control_list() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList><Bogus/></AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_child_in_grant() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                    <Bogus/>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_duplicate_grantee_in_grant() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                        <ID>second</ID>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_duplicate_permission_in_grant() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                    <Permission>WRITE</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_child_in_grantee() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                        <ID>u</ID>\
                        <Bogus/>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_child_in_owner() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID><Bogus/></Owner>\
            <AccessControlList/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_duplicate_id_in_owner() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID><ID>second</ID></Owner>\
            <AccessControlList/>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_accepts_grantee_with_displayname_and_id() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                        <ID>u</ID>\
                        <DisplayName>u-display</DisplayName>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        let acl = acl_from_xml_strict(xml).expect("DisplayName alongside ID is allowed");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].grantee, "u");
    }

    #[test]
    fn strict_rejects_grantee_with_uri_and_id() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                        <ID>some-user</ID>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grantee_with_unknown_uri() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>AllUsers</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grantee_with_uri_pointing_to_unsupported_group() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/s3/LogDelivery</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grantee_with_email_address() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\">\
                        <EmailAddress>user@example.com</EmailAddress>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grantee_with_email_and_id() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\">\
                        <EmailAddress>user@example.com</EmailAddress>\
                        <ID>u</ID>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_grantee_with_only_displayname() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                        <DisplayName>orphan</DisplayName>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_group_grantee_with_displayname() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                        <DisplayName>everyone</DisplayName>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_empty_grantee_element() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"/>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_accepts_authenticated_users_uri() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <URI>http://acs.amazonaws.com/groups/global/AuthenticatedUsers</URI>\
                    </Grantee>\
                    <Permission>WRITE</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        let acl = acl_from_xml_strict(xml).expect("AuthenticatedUsers URI must parse");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].grantee, GRANTEE_AUTHENTICATED_USERS);
    }

    #[test]
    fn strict_rejects_grantee_missing_xsi_type() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee>\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_group_xsi_type_with_id_child() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                        <ID>some-user</ID>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_canonical_user_xsi_type_with_uri_child() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_unknown_xsi_type() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Robot\">\
                        <ID>r2d2</ID>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn strict_rejects_amazon_customer_by_email_xsi_type() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant>\
                    <Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"AmazonCustomerByEmail\">\
                        <EmailAddress>user@example.com</EmailAddress>\
                    </Grantee>\
                    <Permission>READ</Permission>\
                </Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        assert!(acl_from_xml_strict(xml).is_none());
    }

    #[test]
    fn lenient_still_skips_invalid_grants() {
        let xml = "<AccessControlPolicy>\
            <Owner><ID>owner</ID></Owner>\
            <AccessControlList>\
                <Grant><Permission>READ</Permission></Grant>\
                <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>\
                </Grantee><Permission>READ</Permission></Grant>\
            </AccessControlList>\
            </AccessControlPolicy>";
        let acl = acl_from_xml(xml).expect("lenient must still produce an ACL");
        assert_eq!(acl.grants.len(), 1);
        assert_eq!(acl.grants[0].grantee, GRANTEE_ALL_USERS);
    }
}
