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
            if grant.grantee == GRANTEE_ALL_USERS {
                actions.extend(permission_to_actions(&grant.permission));
            } else if grant.grantee == GRANTEE_AUTHENTICATED_USERS && is_authenticated {
                actions.extend(permission_to_actions(&grant.permission));
            } else if let Some(principal_id) = principal_id {
                if grant.grantee == principal_id {
                    actions.extend(permission_to_actions(&grant.permission));
                }
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
        "bucket-owner-read" | "bucket-owner-full-control" | "private" | _ => Acl {
            owner: owner.to_string(),
            grants: vec![owner_grant],
        },
    }
}

pub fn acl_to_xml(acl: &Acl) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>\
         <AccessControlList>",
        xml_escape(&acl.owner),
        xml_escape(&acl.owner),
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
                xml.push_str(&format!(
                    "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                     <ID>{}</ID><DisplayName>{}</DisplayName>\
                     </Grantee>",
                    xml_escape(other),
                    xml_escape(other),
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

fn acl_from_xml(xml: &str) -> Option<Acl> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let owner = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "Owner")
        .and_then(|node| {
            node.children()
                .find(|child| child.is_element() && child.tag_name().name() == "ID")
                .and_then(|child| child.text())
        })
        .unwrap_or("myfsio")
        .trim()
        .to_string();

    let mut grants = Vec::new();
    for grant in doc
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Grant")
    {
        let permission = grant
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Permission")
            .and_then(|child| child.text())
            .unwrap_or_default()
            .trim()
            .to_string();
        if permission.is_empty() {
            continue;
        }
        let grantee_node = grant
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "Grantee");
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
            continue;
        }
        grants.push(AclGrant {
            grantee,
            permission,
        });
    }

    Some(Acl { owner, grants })
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
}
