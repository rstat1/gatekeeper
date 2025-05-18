use std::{env, fs, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let p: String = env::current_dir().unwrap().as_os_str().to_str().unwrap().to_string();

	let gen_file_path = format!("{}/{}", p, "src/services/proto/generated");
	println!("{}", gen_file_path);

	let path = Path::new(&gen_file_path);

	if !path.exists() {
		fs::create_dir_all(path)?; // create_dir_all handles nested directories
	}
	tonic_build::configure()
		.build_client(false)
		.build_transport(false)
		.file_descriptor_set_path(gen_file_path.clone() + "/descriptors.bin")
		.out_dir(gen_file_path.clone())
		.message_attribute("Alias", "#[derive(serde::Serialize, serde::Deserialize)]")
		.message_attribute("Service", "#[derive(serde::Serialize, serde::Deserialize)]")
		.message_attribute("Namespace", "#[derive(serde::Serialize, serde::Deserialize)]")
		.compile_protos(
			&["src/services/proto/types.proto", "src/services/proto/EndpointManager.proto", "src/services/proto/ConfigService.proto"],
			&["src/services/proto"],
		)
		.unwrap();
	Ok(())
}
