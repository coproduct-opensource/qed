//! Checks a JSON value against the vendored A2A JSON Schema bundle, and
//! against the fields the A2A proto marks `REQUIRED`.
//!
//! The bundle uses a small part of JSON Schema 2020-12. This validator
//! implements that part and refuses anything else it meets on the way, so a
//! keyword it does not understand is an error and never a silent pass.
use serde_json::Value;

pub const BUNDLE: &str = include_str!("../vendor/a2a-v1.0.1.schema.json");

/// Keywords that annotate and do not constrain.
const ANNOTATIONS: [&str; 6] = [
    "$schema",
    "title",
    "description",
    "default",
    "examples",
    "format",
];

#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub what: String,
}

pub struct Bundle {
    definitions: serde_json::Map<String, Value>,
}

impl Bundle {
    pub fn vendored() -> Self {
        let value: Value = serde_json::from_str(BUNDLE).expect("the vendored bundle is JSON");
        let definitions = value["definitions"]
            .as_object()
            .expect("the vendored bundle has definitions")
            .clone();
        Self { definitions }
    }

    /// A definition by its message name, such as `AgentCard`. The bundle's
    /// keys are the same names with spaces between words.
    fn definition(&self, name: &str) -> Option<&Value> {
        self.definitions
            .iter()
            .find(|(key, _)| key.replace(' ', "") == name)
            .map(|(_, value)| value)
    }

    /// `lf.a2a.v1.AgentSkill.jsonschema.json` names the definition `AgentSkill`.
    fn resolve(&self, reference: &str) -> Option<&Value> {
        let stem = reference.strip_suffix(".jsonschema.json")?;
        self.definition(stem.rsplit('.').next()?)
    }

    pub fn check(&self, name: &str, value: &Value) -> Vec<Violation> {
        let mut out = Vec::new();
        match self.definition(name) {
            Some(schema) => self.walk(schema, value, name, &mut out),
            None => out.push(Violation {
                path: name.into(),
                what: "no such definition in the bundle".into(),
            }),
        }
        out
    }

    fn walk(&self, schema: &Value, value: &Value, path: &str, out: &mut Vec<Violation>) {
        let mut fail = |what: String| {
            out.push(Violation {
                path: path.into(),
                what,
            })
        };
        let Some(schema) = schema.as_object() else {
            return fail("schema is not an object".into());
        };
        // Collected first: `fail` borrows `out`, and recursion needs it too.
        let mut children: Vec<(&Value, &Value, String)> = Vec::new();
        for (keyword, rule) in schema {
            match keyword.as_str() {
                k if ANNOTATIONS.contains(&k) => {}
                "$ref" => match rule.as_str().and_then(|r| self.resolve(r)) {
                    Some(target) => children.push((target, value, path.to_owned())),
                    None => fail(format!("unresolved reference {rule}")),
                },
                "type" => {
                    let wanted = rule.as_str().unwrap_or("");
                    let is = match wanted {
                        "object" => value.is_object(),
                        "array" => value.is_array(),
                        "string" => value.is_string(),
                        "boolean" => value.is_boolean(),
                        "integer" => value.is_i64() || value.is_u64(),
                        "number" => value.is_number(),
                        _ => {
                            fail(format!("unsupported type {rule}"));
                            true
                        }
                    };
                    if !is {
                        fail(format!("expected {wanted}"));
                    }
                }
                "enum" => {
                    if !rule
                        .as_array()
                        .is_some_and(|options| options.contains(value))
                    {
                        fail(format!("not one of {rule}"));
                    }
                }
                "items" => {
                    if let Some(items) = value.as_array() {
                        for (index, item) in items.iter().enumerate() {
                            children.push((rule, item, format!("{path}[{index}]")));
                        }
                    }
                }
                // Handled together below.
                "properties" | "patternProperties" | "additionalProperties" | "propertyNames" => {}
                other => fail(format!("unsupported keyword {other}")),
            }
        }
        if let Some(object) = value.as_object() {
            let properties = schema.get("properties").and_then(Value::as_object);
            let patterns = schema.get("patternProperties").and_then(Value::as_object);
            for (key, member) in object {
                let here = format!("{path}.{key}");
                if let Some(rule) = properties.and_then(|p| p.get(key)) {
                    children.push((rule, member, here));
                    continue;
                }
                // The bundle's patterns are all `^(literal)$`: the proto's
                // snake_case spelling of a property.
                let by_pattern = patterns.and_then(|p| {
                    p.iter()
                        .find(|(pattern, _)| {
                            pattern
                                .strip_prefix("^(")
                                .and_then(|rest| rest.strip_suffix(")$"))
                                == Some(key.as_str())
                        })
                        .map(|(_, rule)| rule)
                });
                if let Some(rule) = by_pattern {
                    children.push((rule, member, here));
                    continue;
                }
                match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => out.push(Violation {
                        path: here,
                        what: "property not in the schema".into(),
                    }),
                    Some(Value::Bool(true)) | None => {}
                    Some(rule) => children.push((rule, member, here)),
                }
            }
            if let Some(patterns) = patterns {
                for pattern in patterns.keys() {
                    if !(pattern.starts_with("^(") && pattern.ends_with(")$")) {
                        out.push(Violation {
                            path: path.into(),
                            what: format!("unsupported pattern {pattern}"),
                        });
                    }
                }
            }
        }
        for (rule, member, here) in children {
            self.walk(rule, member, &here, out);
        }
    }
}

/// The fields `specification/a2a.proto` at tag v1.0.1 marks `REQUIRED` on an
/// Agent Card and the messages a card contains. The JSON bundle does not
/// carry them.
pub fn required(card: &Value) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut need = |value: &Value, path: &str, fields: &[&str]| {
        for field in fields {
            if value.get(field).is_none() {
                out.push(Violation {
                    path: format!("{path}.{field}"),
                    what: "required by the proto and absent".into(),
                });
            }
        }
    };
    need(
        card,
        "AgentCard",
        &[
            "name",
            "description",
            "supportedInterfaces",
            "version",
            "capabilities",
            "defaultInputModes",
            "defaultOutputModes",
            "skills",
        ],
    );
    for (index, interface) in list(card, "supportedInterfaces").iter().enumerate() {
        need(
            interface,
            &format!("AgentCard.supportedInterfaces[{index}]"),
            &["url", "protocolBinding", "protocolVersion"],
        );
    }
    for (index, skill) in list(card, "skills").iter().enumerate() {
        need(
            skill,
            &format!("AgentCard.skills[{index}]"),
            &["id", "name", "description", "tags"],
        );
    }
    if let Some(provider) = card.get("provider") {
        need(provider, "AgentCard.provider", &["url", "organization"]);
    }
    for (index, signature) in list(card, "signatures").iter().enumerate() {
        need(
            signature,
            &format!("AgentCard.signatures[{index}]"),
            &["protected", "signature"],
        );
    }
    out
}

fn list<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}
