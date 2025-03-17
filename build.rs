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
		.include_file(format!("{}/{}", gen_file_path.clone(), "gen.rs"))
		.file_descriptor_set_path(gen_file_path.clone() + "/descriptors.bin")
		.out_dir(gen_file_path.clone())
		.compile_protos(&["src/services/proto/types.proto", "src/services/proto/APIService.proto"], &["src/services/proto"])
		.unwrap();
	Ok(())
}
