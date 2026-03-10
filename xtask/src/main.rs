// Copyright 2026 Silence Laboratories Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    env,
    path::PathBuf,
    process::{Command, ExitCode},
};

use serde_json::Value;

struct FeatureMatrixArgs {
    command: String,
    packages: Vec<String>,
    dry_run: bool,
    cargo_args: Vec<String>,
}

fn main() -> ExitCode {
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("feature-matrix") => run_feature_matrix(args.collect()),
        _ => Err(usage()),
    }
}

fn run_feature_matrix(args: Vec<String>) -> Result<(), String> {
    let args = parse_feature_matrix_args(args)?;
    let workspace_root = workspace_root()?;
    let metadata = cargo_metadata(&workspace_root)?;
    let all_packages = workspace_packages(&metadata)?;
    let selected_packages = select_packages(all_packages, &args.packages)?;

    let mut command_count = 0usize;
    for package in selected_packages {
        for (label, feature_args) in feature_combinations(&package)? {
            let cargo_command = cargo_command(
                &args.command,
                &package.name,
                &feature_args,
                &args.cargo_args,
            );
            println!("==> {} [{}]", package.name, label);
            println!("{}", join_command(&cargo_command));
            command_count += 1;

            if !args.dry_run {
                let status = Command::new(&cargo_command[0])
                    .args(&cargo_command[1..])
                    .current_dir(&workspace_root)
                    .status()
                    .map_err(|err| {
                        format!(
                            "failed to run {}: {err}",
                            join_command(&cargo_command)
                        )
                    })?;

                if !status.success() {
                    return Err(format!(
                        "command failed with status {}: {}",
                        status,
                        join_command(&cargo_command)
                    ));
                }
            }
        }
    }

    println!("Executed {command_count} command(s).");

    Ok(())
}

fn usage() -> String {
    "usage: cargo run -p xtask -- feature-matrix <clippy|test> [--package <name> ...] [--dry-run] [-- <cargo args...>]"
        .to_owned()
}

fn parse_feature_matrix_args(
    args: Vec<String>,
) -> Result<FeatureMatrixArgs, String> {
    let mut command = None;
    let mut packages = Vec::new();
    let mut dry_run = false;
    let mut cargo_args = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "clippy" | "test" if command.is_none() => command = Some(arg),
            "--package" => {
                let package = iter.next().ok_or_else(|| {
                    "--package requires a package name".to_owned()
                })?;
                packages.push(package);
            }
            "--dry-run" => dry_run = true,
            "--" => {
                cargo_args.extend(iter);
                break;
            }
            _ => return Err(usage()),
        }
    }

    Ok(FeatureMatrixArgs {
        command: command.ok_or_else(usage)?,
        packages,
        dry_run,
        cargo_args,
    })
}

fn workspace_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| "failed to determine workspace root".to_owned())
}

fn cargo_metadata(workspace_root: &PathBuf) -> Result<Value, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root)
        .output()
        .map_err(|err| format!("failed to run cargo metadata: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed with status {}",
            output.status
        ));
    }

    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("failed to parse cargo metadata JSON: {err}"))
}

#[derive(Clone)]
struct Package {
    name: String,
    features: Vec<String>,
    default_features: Vec<String>,
}

fn implicit_optional_dependency_features(
    package: &Value,
    feature_map: &serde_json::Map<String, Value>,
) -> BTreeSet<String> {
    let optional_dependencies = package["dependencies"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|dependency| dependency["optional"].as_bool() == Some(true))
        .filter_map(|dependency| dependency["name"].as_str())
        .collect::<BTreeSet<_>>();

    feature_map
        .iter()
        .filter_map(|(feature, members)| {
            let members = members.as_array()?;
            if members.len() != 1 {
                return None;
            }

            let member = members[0].as_str()?;
            (member == format!("dep:{feature}")
                && optional_dependencies.contains(feature.as_str()))
            .then(|| feature.clone())
        })
        .collect()
}

fn workspace_packages(metadata: &Value) -> Result<Vec<Package>, String> {
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| {
            "cargo metadata is missing workspace_members".to_owned()
        })?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    let mut packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| "cargo metadata is missing packages".to_owned())?
        .iter()
        .filter_map(|package| {
            let id = package["id"].as_str()?;
            if !workspace_members.contains(id) {
                return None;
            }

            let name = package["name"].as_str()?.to_owned();
            let feature_map = package["features"].as_object()?;
            let implicit_optional_features =
                implicit_optional_dependency_features(package, feature_map);
            let mut features = feature_map
                .keys()
                .filter(|feature| feature.as_str() != "default")
                .filter(|feature| {
                    !implicit_optional_features.contains(feature.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            features.sort();

            let mut default_features = feature_map
                .get("default")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|feature| {
                    !implicit_optional_features.contains(*feature)
                })
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            default_features.sort();

            Some(Package {
                name,
                features,
                default_features,
            })
        })
        .collect::<Vec<_>>();

    packages.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(packages)
}

fn select_packages(
    all_packages: Vec<Package>,
    names: &[String],
) -> Result<Vec<Package>, String> {
    if names.is_empty() {
        return Ok(all_packages);
    }

    let requested = names.iter().cloned().collect::<BTreeSet<_>>();
    let selected = all_packages
        .into_iter()
        .filter(|package| requested.contains(&package.name))
        .collect::<Vec<_>>();

    let found = selected
        .iter()
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    let missing = requested.difference(&found).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "unknown workspace package(s): {}",
            missing.join(", ")
        ));
    }

    Ok(selected)
}

fn feature_combinations(
    package: &Package,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let default_selectable = package
        .default_features
        .iter()
        .filter(|feature| package.features.contains(*feature))
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut combinations = Vec::new();
    let mut seen = BTreeSet::new();

    add_combination(
        &mut combinations,
        &mut seen,
        "default".to_owned(),
        Vec::new(),
    );

    if package.default_features.is_empty() {
        for subset in subsets(&package.features) {
            if subset.is_empty() {
                continue;
            }
            let label = subset.join(",");
            let args = vec!["--features".to_owned(), label.clone()];
            add_combination(&mut combinations, &mut seen, label, args);
        }
        return Ok(combinations);
    }

    add_combination(
        &mut combinations,
        &mut seen,
        "no-default".to_owned(),
        vec!["--no-default-features".to_owned()],
    );

    for subset in subsets(&package.features) {
        if subset.is_empty() {
            continue;
        }
        let joined = subset.join(",");
        add_combination(
            &mut combinations,
            &mut seen,
            format!("no-default+{joined}"),
            vec![
                "--no-default-features".to_owned(),
                "--features".to_owned(),
                joined,
            ],
        );
    }

    let default_extras = package
        .features
        .iter()
        .filter(|feature| !default_selectable.contains(feature.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    for subset in subsets(&default_extras) {
        if subset.is_empty() {
            continue;
        }
        let joined = subset.join(",");
        add_combination(
            &mut combinations,
            &mut seen,
            format!("default+{joined}"),
            vec!["--features".to_owned(), joined],
        );
    }

    Ok(combinations)
}

fn add_combination(
    combinations: &mut Vec<(String, Vec<String>)>,
    seen: &mut BTreeSet<Vec<String>>,
    label: String,
    args: Vec<String>,
) {
    if seen.insert(args.clone()) {
        combinations.push((label, args));
    }
}

fn subsets(items: &[String]) -> Vec<Vec<String>> {
    let count = 1usize << items.len();
    let mut subsets = Vec::with_capacity(count);

    for mask in 0..count {
        let mut subset = Vec::new();
        for (index, item) in items.iter().enumerate() {
            if (mask & (1usize << index)) != 0 {
                subset.push(item.clone());
            }
        }
        subsets.push(subset);
    }

    subsets
}

fn cargo_command(
    command: &str,
    package: &str,
    feature_args: &[String],
    cargo_args: &[String],
) -> Vec<String> {
    let mut args = vec![
        "cargo".to_owned(),
        command.to_owned(),
        "--package".to_owned(),
        package.to_owned(),
    ];

    args.extend(feature_args.iter().cloned());
    args.extend(cargo_args.iter().cloned());

    if command == "clippy" {
        args.push("--".to_owned());
        args.push("-D".to_owned());
        args.push("warnings".to_owned());
    }

    args
}

fn join_command(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.chars().all(|ch| {
                ch.is_ascii_alphanumeric() || "-_.,/=:".contains(ch)
            }) {
                arg.clone()
            } else {
                format!("{arg:?}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_feature_matrix_args_collects_cargo_args_after_separator() {
        let args = parse_feature_matrix_args(vec![
            "test".to_owned(),
            "--package".to_owned(),
            "sl-paillier".to_owned(),
            "--dry-run".to_owned(),
            "--".to_owned(),
            "--release".to_owned(),
            "--locked".to_owned(),
        ])
        .unwrap();

        assert_eq!(args.command, "test");
        assert_eq!(args.packages, vec!["sl-paillier"]);
        assert!(args.dry_run);
        assert_eq!(args.cargo_args, vec!["--release", "--locked"]);
    }

    #[test]
    fn cargo_command_places_forwarded_args_before_clippy_lints() {
        let command = cargo_command(
            "clippy",
            "xtask",
            &["--features".to_owned(), "serde".to_owned()],
            &["--release".to_owned()],
        );

        assert_eq!(
            command,
            vec![
                "cargo",
                "clippy",
                "--package",
                "xtask",
                "--features",
                "serde",
                "--release",
                "--",
                "-D",
                "warnings",
            ]
        );
    }

    #[test]
    fn filters_implicit_optional_dependency_features() {
        let package = serde_json::json!({
            "dependencies": [
                { "name": "tokio", "optional": true },
                { "name": "fastwebsockets", "optional": true },
                { "name": "serde", "optional": false }
            ],
            "features": {
                "default": [],
                "tokio": ["dep:tokio"],
                "fastwebsockets": ["dep:fastwebsockets"],
                "mux": ["tokio/macros", "tokio/rt"],
                "fast-ws": ["fastwebsockets", "tokio/macros"]
            }
        });

        let feature_map = package["features"].as_object().unwrap();
        let implicit =
            implicit_optional_dependency_features(&package, feature_map);

        assert_eq!(
            implicit,
            BTreeSet::from(["fastwebsockets".to_owned(), "tokio".to_owned()])
        );
    }
}
