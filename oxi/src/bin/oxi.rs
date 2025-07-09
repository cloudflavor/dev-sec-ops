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

use anyhow::{Context, Result};
use oxi::{load_toml_files, parser, Cli};
use structopt::StructOpt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Cli::from_args();

    let opts_level = opts.log_level;
    let env_filter = EnvFilter::new(opts_level.as_str());

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_ansi(true)
        .with_env_filter(env_filter)
        .with_writer(std::io::stdout)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match opts.commands {
        oxi::Commands::Generate(args) => {
            let toml_files = load_toml_files(args.rules_dir)
                .await
                .with_context(|| "failed to parse TOML files")?;
            let rules = parser::deserialize_rules(toml_files)
                .await
                .with_context(|| "failed to deserialize TOML")?;

            match args.output {
                oxi::OutputOpts::Stdout => {
                    let cloudflare_rules = parser::generate_cloudflare_rules(rules)
                        .with_context(|| "failed to generate Cloudflare rules")?;

                    for rule in cloudflare_rules.iter() {
                        println!("{:#?}", rule);
                    }
                }
                oxi::OutputOpts::Terraform => {
                    let terraform_tfvars = parser::generate_terraform_tfvars(rules)
                        .with_context(|| "failed to generate terraform.tfvars")?;

                    for (file, data) in terraform_tfvars.into_iter() {
                        for rule in data.iter() {
                            tokio::fs::write(&file, &rule).await.with_context(|| {
                                "failed to write generated terraform data to files"
                            })?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
