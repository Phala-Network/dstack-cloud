// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use fs_err as fs;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

/// Holds parsed information from a docker-compose file
#[derive(Debug)]
pub struct ComposeInfo {
    pub project_name: String,
    pub service_names: std::collections::HashSet<String>,
}

/// Parse a docker-compose file and extract project name and service names
pub fn parse_docker_compose_file(compose_file: impl AsRef<Path>) -> Result<ComposeInfo> {
    let compose_content =
        fs::read_to_string(compose_file.as_ref()).context("failed to read docker-compose file")?;

    let yaml_docs = YamlLoader::load_from_str(&compose_content).context("failed to parse YAML")?;
    let yaml_doc = yaml_docs.first().context("empty YAML document")?;

    // Extract project name
    let project_name = if let Some(name) = yaml_doc["name"].as_str() {
        name.to_string()
    } else {
        get_project_name(compose_file.as_ref())?
    };

    // Extract service names
    let services = match &yaml_doc["services"] {
        Yaml::Hash(m) => m,
        _ => anyhow::bail!("missing or invalid 'services' field"),
    };

    let service_names = services
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();

    Ok(ComposeInfo {
        project_name,
        service_names,
    })
}

fn get_project_name(compose_file: impl AsRef<Path>) -> Result<String> {
    let project_name = fs::canonicalize(compose_file)
        .context("failed to canonicalize compose file")?
        .parent()
        .context("failed to get parent directory of compose file")?
        .file_name()
        .context("failed to get file name of compose file")?
        .to_string_lossy()
        .into_owned();
    Ok(project_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_anchor_parsing() {
        // Test that yaml-rust2 can parse YAML anchors and aliases
        let yaml_with_anchors = r#"
name: test-project
services:
  common: &common-config
    image: ubuntu:latest
    restart: unless-stopped

  service1:
    <<: *common-config
    container_name: service1

  service2:
    <<: *common-config
    container_name: service2

  service3:
    image: nginx:latest
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_with_anchors).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        // Extract project name
        let project_name = yaml_doc["name"].as_str().unwrap();
        assert_eq!(project_name, "test-project");

        // Extract service names
        let services = match &yaml_doc["services"] {
            Yaml::Hash(m) => m,
            _ => panic!("services should be a hash"),
        };

        let service_names: std::collections::HashSet<String> = services
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect();

        // Verify all services are parsed including the anchor definition
        assert_eq!(service_names.len(), 4);
        assert!(service_names.contains("common"));
        assert!(service_names.contains("service1"));
        assert!(service_names.contains("service2"));
        assert!(service_names.contains("service3"));

        // Verify that anchors are resolved
        // Note: yaml-rust2 parses anchors but doesn't auto-expand merge keys
        // The merge key "<<" will contain the referenced hash
        let service1 = &yaml_doc["services"]["service1"];
        assert_eq!(service1["container_name"].as_str().unwrap(), "service1");

        // Verify the merge key contains the anchor content
        if let Yaml::Hash(merge_content) = &service1["<<"] {
            assert_eq!(
                merge_content[&Yaml::String("image".to_string())]
                    .as_str()
                    .unwrap(),
                "ubuntu:latest"
            );
            assert_eq!(
                merge_content[&Yaml::String("restart".to_string())]
                    .as_str()
                    .unwrap(),
                "unless-stopped"
            );
        } else {
            panic!("merge key should contain hash");
        }
    }

    #[test]
    fn test_yaml_simple_anchor_alias() {
        // Test simple anchor and alias without merge keys
        let yaml_simple_anchor = r#"
defaults: &defaults
  timeout: 30
  retries: 3

service1:
  name: web
  config: *defaults

service2:
  name: api
  config: *defaults
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_simple_anchor).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        // Verify alias points to the same content
        let service1_config = &yaml_doc["service1"]["config"];
        let service2_config = &yaml_doc["service2"]["config"];

        assert_eq!(service1_config["timeout"].as_i64().unwrap(), 30);
        assert_eq!(service1_config["retries"].as_i64().unwrap(), 3);
        assert_eq!(service2_config["timeout"].as_i64().unwrap(), 30);
        assert_eq!(service2_config["retries"].as_i64().unwrap(), 3);
    }

    #[test]
    fn test_yaml_without_anchors() {
        let yaml_simple = r#"
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"#;

        let yaml_docs = YamlLoader::load_from_str(yaml_simple).unwrap();
        let yaml_doc = yaml_docs.first().unwrap();

        let services = match &yaml_doc["services"] {
            Yaml::Hash(m) => m,
            _ => panic!("services should be a hash"),
        };

        let service_names: std::collections::HashSet<String> = services
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect();

        assert_eq!(service_names.len(), 2);
        assert!(service_names.contains("web"));
        assert!(service_names.contains("db"));
    }

    #[test]
    fn test_parse_real_compose_file() {
        // Test with real docker-compose.yaml from key-provider-build
        let compose_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/key-provider-docker-compose.yaml"
        );

        let compose_info = parse_docker_compose_file(compose_path).unwrap();

        // Verify service names are correctly extracted
        assert_eq!(compose_info.service_names.len(), 2);
        assert!(compose_info.service_names.contains("aesmd"));
        assert!(compose_info
            .service_names
            .contains("gramine-sealing-key-provider"));

        // Note: x-common is an anchor definition, not a service, so it should not be in service_names
        assert!(!compose_info.service_names.contains("x-common"));

        // Project name should be "fixtures" (the parent directory name)
        assert_eq!(compose_info.project_name, "fixtures");
    }
}
