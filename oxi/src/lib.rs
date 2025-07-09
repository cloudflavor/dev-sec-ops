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

pub mod parser;

use anyhow::{Context, Result};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use structopt::StructOpt;
use tokio::fs;

#[derive(StructOpt)]
pub struct Cli {
    #[structopt(
        short,
        long,
        default_value = "info",
        possible_values = &["trace", "debug", "info", "warn", "error"]
    )]
    pub log_level: tracing::Level,

    #[structopt(subcommand)]
    pub commands: Commands,
}

#[derive(StructOpt, Debug)]
pub enum Commands {
    Generate(Inputs),
}

#[derive(StructOpt, Debug)]
pub struct Inputs {
    /// The directory where the WAF rules are stored
    #[structopt(short, long)]
    pub rules_dir: PathBuf,

    /// By default the generated Cloudflare rules are written to STDOUT.
    /// The user can copy them directly and create the rules manually in the UI.
    /// They can also be written to terraform files with --output terraform,
    /// this will create terraform.tfvars that can be later ingested as part
    /// of a terraform module.
    #[structopt(short, long, default_value = "stdout", possible_values = &["stdout", "terraform"])]
    pub output: OutputOpts,

    #[structopt(short("d"), long)]
    pub output_dir: Option<PathBuf>,
}

#[derive(StructOpt, Debug)]
pub enum OutputOpts {
    Stdout,
    Terraform,
}

impl FromStr for OutputOpts {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stdout" => Ok(OutputOpts::Stdout),
            "terraform" => Ok(OutputOpts::Terraform),
            _ => Err(format!("invalid mode: {s}")),
        }
    }
}

pub async fn load_toml_files(waf_dir: impl AsRef<Path>) -> Result<Vec<String>> {
    let mut files = fs::read_dir(&waf_dir)
        .await
        .with_context(|| "failed to read dir: {e}")?;

    let mut toml_data = Vec::new();

    while let Some(entry) = files.next_entry().await? {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("toml") {
            tracing::info!("found: {:?}", entry.file_name());

            match fs::read_to_string(entry.path()).await {
                Ok(file_data) => toml_data.push(file_data),
                Err(e) => {
                    tracing::error!("failed to read file {}  :{e}", entry.path().display());
                    continue;
                }
            }
        }
    }

    if !toml_data.is_empty() {
        Ok(toml_data)
    } else {
        Err(anyhow::format_err!(
            "no TOML files were found in {:?}",
            waf_dir.as_ref().display()
        ))
    }
}
