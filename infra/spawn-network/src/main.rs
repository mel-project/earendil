use regex::Regex;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::{rename, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Deserialize)]
struct Adjacencies {
    adjacencies: Vec<(String, String)>,
}

fn main() -> anyhow::Result<()> {
    let infra_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let topology_path = infra_dir.join("topology.yaml");
    let terraform_dir = infra_dir.join("terraform");
    let tfvars_path = terraform_dir.join("terraform.tfvars");

    populate_node_list(&topology_path, &tfvars_path)?;
    provision_nodes(&terraform_dir)?;

    // Generate Earendil configs.
    let config_output_dir_name = "generated_earendil_configs";
    generate_earendil_configs(&topology_path, config_output_dir_name)?;
    let config_output_dir = infra_dir.join(config_output_dir_name);

    // light processing on the file names
    rename_configs_in_directory(&config_output_dir)?;

    // Replace localhost values with node IPs.
    let node_ips = get_node_ips(&terraform_dir)?;
    update_out_routes_in_configs(&config_output_dir, &node_ips)?;

    // TODO: compile `earendil` and rsync the binary + config file to the corresponding server
    // TODO: on each server, set up a systemd service and run the earendil nodes

    Ok(())
}

fn populate_node_list(topology_path: &PathBuf, tfvars_path: &PathBuf) -> anyhow::Result<()> {
    let file = File::open(topology_path)?;
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

fn provision_nodes(terraform_dir: &PathBuf) -> anyhow::Result<()> {
    Command::new("terraform")
        .arg("init")
        .current_dir(terraform_dir)
        .status()?;

    Command::new("terraform")
        .arg("apply")
        .arg("-auto-approve")
        .current_dir(terraform_dir)
        .status()?;

    Ok(())
}

fn get_node_ips(terraform_dir: &PathBuf) -> anyhow::Result<HashMap<String, String>> {
    let output = Command::new("terraform")
        .arg("output")
        .arg("-json")
        .arg("node_ips")
        .current_dir(terraform_dir)
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to get Terraform outputs: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let ips_json = String::from_utf8(output.stdout)?;
    let ips: HashMap<String, String> = serde_json::from_str(&ips_json)?;

    println!("node IPs {:?}", ips);

    Ok(ips)
}

fn generate_earendil_configs(topology_path: &PathBuf, output_dir_name: &str) -> anyhow::Result<()> {
    // Call the installed gen-earendil-shadow executable with the given arguments
    Command::new("gen-earendil-shadow")
        .args([topology_path.to_str().unwrap(), output_dir_name])
        .status()?;
    Ok(())
}

fn rename_configs_in_directory(config_output_dir: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(config_output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let file_name = entry.file_name();
            let new_file_name = file_name.to_string_lossy().replace("-cfg", "");
            let new_path = path.with_file_name(new_file_name);
            std::fs::rename(path, new_path)?;
        }
    }
    Ok(())
}

fn update_out_routes_in_configs(
    config_output_dir: &Path,
    node_ips: &HashMap<String, String>,
) -> anyhow::Result<()> {
    // Compile a regex to find the out_routes' connect field
    let re = Regex::new(r"out_routes:\s*\n(\s*(.*?):\s*\n\s*connect: )127\.0\.0\.1(:\d+)")?;

    for entry in std::fs::read_dir(config_output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let contents = std::fs::read_to_string(&path)?;
            let updated_contents = re.replace_all(&contents, |caps: &regex::Captures| {
                // Get the node name from the second capture group
                if let Some(node_name) = caps.get(2).map(|m| m.as_str()) {
                    // Look up the corresponding IP address
                    if let Some(ip) = node_ips.get(node_name) {
                        // Replace 127.0.0.1 with the actual IP address
                        format!("{}{}{}", &caps[1], ip, &caps[3])
                    } else {
                        // If no IP found for the node name, keep the original text
                        caps[0].to_string()
                    }
                } else {
                    // If the node name capture group is not found, keep the original text
                    caps[0].to_string()
                }
            });
            std::fs::write(path, updated_contents.as_bytes())?;
        }
    }
    Ok(())
}
