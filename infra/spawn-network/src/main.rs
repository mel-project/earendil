use regex::Regex;
use serde::Deserialize;
use std::{collections::HashSet, fs::File, io::Read, path::PathBuf, process::Command};

fn main() -> anyhow::Result<()> {
    let infra_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let yaml_path = infra_dir.join("topology.yaml");
    let terraform_dir = infra_dir.join("terraform");
    let tfvars_path = terraform_dir.join("terraform.tfvars");

    populate_node_list(&yaml_path, &tfvars_path)?;
    provision_nodes(terraform_dir)?;

    Ok(())
}

fn populate_node_list(adjacencies_path: &PathBuf, tfvars_path: &PathBuf) -> anyhow::Result<()> {
    let file = File::open(adjacencies_path)?;
    let adjacencies: Adjacencies =
        serde_yaml::from_reader(file).expect("Error parsing the adjacency YAML file");

    // Extract unique node names from adjacencies
    let nodes_from_adjacencies: HashSet<String> = adjacencies
        .adjacencies
        .into_iter()
        .flat_map(|(node1, node2)| vec![node1, node2])
        .collect();

    let node_list = nodes_from_adjacencies
        .iter()
        .map(|node| format!("\"{}\"", node))
        .collect::<Vec<String>>()
        .join(", ");

    println!("node_list: {node_list}");

    // Update the existing node_names entry in the .tfvars file
    let mut tfvars_content = String::new();
    File::open(tfvars_path)?.read_to_string(&mut tfvars_content)?;
    let re_node_names = Regex::new(r"node_names\s*=\s*\[[^\]]*\]")?;
    if re_node_names.is_match(&tfvars_content) {
        tfvars_content = re_node_names
            .replace(
                &tfvars_content,
                format!("node_names = [{}]", node_list).as_str(),
            )
            .to_string();
    } else {
        tfvars_content.push_str(&format!("\nnode_names = [{}]\n", node_list));
    }

    std::fs::write(tfvars_path, tfvars_content)?;

    Ok(())
}

fn provision_nodes(terraform_dir: PathBuf) -> anyhow::Result<()> {
    Command::new("terraform")
        .arg("init")
        .current_dir(&terraform_dir)
        .status()?;

    Command::new("terraform")
        .arg("apply")
        .arg("-auto-approve")
        .current_dir(&terraform_dir)
        .status()?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Adjacencies {
    adjacencies: Vec<(String, String)>,
}
