// Copyright 2025 Cloudflavor GmbH

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Result;
use serde::Deserialize;
use std::{collections::HashMap, ptr::copy_nonoverlapping};
use toml;

pub async fn deserialize_rules(toml_files: Vec<String>) -> Result<Vec<RuleFile>> {
    let mut rules = Vec::new();

    for file in toml_files.into_iter() {
        let rule: RuleFile = toml::from_str(file.as_str())?;
        rules.push(rule);
    }

    Ok(rules)
}

pub fn generate_cloudflare_rules(rules: Vec<RuleFile>) -> Result<Vec<String>> {
    for rule in rules.iter() {
        for (i, rule_or_group) in rule.group.rules.iter().enumerate() {
            match rule_or_group {
                RuleOrGroup::Rule(group_rule) => {
                    let connector = if i < rule.group.rules.len() - 1 {
                        format!(" {} ", rule.group.operator)
                    } else {
                        String::new()
                    };

                    println!(
                        "({} {} \"{}\") {}",
                        group_rule.field, group_rule.operator, group_rule.value, connector
                    );
                }
                RuleOrGroup::Nested { operator, sub } => {}
            }
        }
    }

    Ok(Vec::new())
}

pub fn generate_terraform_tfvars(rules: Vec<RuleFile>) -> Result<HashMap<String, Vec<String>>> {
    Ok(HashMap::new())
}

#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub name: String,
    pub action: String,
    pub precedence: u32,
    pub group: Group,
}

#[derive(Debug, Deserialize)]
pub struct Group {
    pub operator: String,
    pub rules: Vec<RuleOrGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RuleOrGroup {
    Rule(Rule),
    Nested { operator: String, sub: Vec<Rule> },
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub field: String,
    pub operator: String,
    pub value: String,
}
