use regex::Regex;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::NamedTempFile;

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

    let earendil_dir = infra_dir.parent().unwrap().to_path_buf();
    let earendil_binary_path =
        earendil_dir.join("target/x86_64-unknown-linux-musl/release/earendil");
    let systemd_service_path = infra_dir.join("earendil_systemd.service");

    run_earendil_nodes_remote(
        &node_ips,
        &earendil_binary_path,
        &config_output_dir,
        &systemd_service_path,
    )?;

    Ok(())
}

fn run_remote_earendil_once(
    node_name: &str,
    ip: &str,
    local_binary_path: &Path,
    local_config_dir: &Path,
    local_service_config: &Path,
) -> anyhow::Result<()> {
    let remote_user = "root";
    let remote_binary_path = format!("{}@{}:/usr/local/bin/earendil", remote_user, ip);
    let remote_config_dir = "/etc/earendil";

    Command::new("ssh")
        .args([
            &format!("{}@{}", remote_user, ip),
            "sudo systemctl stop earendil.service",
        ])
        .status()?;

    // rsync the binary
    Command::new("rsync")
        .args([
            "-avz",
            "--progress",
            "--inplace",
            local_binary_path.to_str().unwrap(),
            &remote_binary_path,
        ])
        .status()?;

    // Ensure the remote configuration directory exists
    Command::new("ssh")
        .args([
            &format!("{}@{}", remote_user, ip),
            &format!("sudo mkdir -p {}", remote_config_dir),
        ])
        .status()?;

    // rsync the config file
    let config_file_name = format!("{}.yaml", node_name);
    let config_file_path = local_config_dir.join(&config_file_name);
    let remote_config_dest = format!(
        "{}@{}:{}/{}",
        remote_user, ip, remote_config_dir, config_file_name
    );
    Command::new("rsync")
        .args([
            "-avz",
            "--progress",
            "--inplace",
            config_file_path.to_str().unwrap(),
            &remote_config_dest,
        ])
        .status()?;

    // Create a modified copy of the systemd service file
    let mut service_config_content = String::new();
    File::open(local_service_config)?.read_to_string(&mut service_config_content)?;
    let remote_config_path = format!("{}/{}", remote_config_dir, config_file_name);
    println!("remote config path: {remote_config_path}");
    let modified_service_content = service_config_content.replace(
        "--config CONFIG_PLACEHOLDER",
        &format!("--config {}", remote_config_path),
    );

    // Write the modified content to a temporary file
    let mut temp_service_file = NamedTempFile::new()?;
    temp_service_file.write_all(modified_service_content.as_bytes())?;

    // Rsync the temporary systemd service file
    let remote_service_path = format!(
        "{}@{}:/etc/systemd/system/earendil.service",
        remote_user, ip
    );
    Command::new("rsync")
        .args([
            "-avz",
            "--progress",
            "--inplace",
            temp_service_file.path().to_str().unwrap(),
            &remote_service_path,
        ])
        .status()?;

    // Reload the systemd daemon to recognize the new service file
    Command::new("ssh")
        .args([
            &format!("{}@{}", remote_user, ip),
            "sudo systemctl daemon-reload",
        ])
        .status()?;

    // Enable and start the systemd service on the remote machine
    // Restart the systemd service on the remote machine
    Command::new("ssh")
    .args([
        &format!("{}@{}", remote_user, ip),
        "sudo systemctl enable --now earendil.service && sudo systemctl restart earendil.service",
    ])
    .status()?;

    // the temporary file will be deleted when it goes out of scope here
    println!("Completed setup for {node_name} on remote {ip}");

    Ok(())
}

fn run_earendil_nodes_remote(
    node_ips: &HashMap<String, String>,
    local_binary_path: &Path,
    local_config_dir: &Path,
    local_service_config: &Path,
) -> anyhow::Result<()> {
    if !local_binary_path.exists() {
        panic!("earendil release binary not found. Please build it in release mode first.");
    }

    for (node_name, ip) in node_ips.iter() {
        run_remote_earendil_once(
            node_name,
            ip,
            local_binary_path,
            local_config_dir,
            local_service_config,
        )?;
    }

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

fn generate_earendil_configs(topology_path: &Path, output_dir_name: &str) -> anyhow::Result<()> {
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
    // Compile a regex to find the out_routes' connect field with the correct pattern
    let re = Regex::new(r"(out_routes:\s*\n\s*)(\w+):\s*\n(\s*)(connect: )127\.0\.0\.1(:\d+)")?;

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
                        // Replace 127.0.0.1 with the actual IP address, preserving the whitespace and newline
                        format!(
                            "{}{}:\n{}{}{}{}",
                            &caps[1], node_name, &caps[3], &caps[4], ip, &caps[5]
                        )
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
