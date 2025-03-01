fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(false)
        .build_transport(false)
        .file_descriptor_set_path("src/services/proto/service_registry/generated/svcregistry_descriptor.bin")
        .out_dir("src/services/proto/service_registry/generated")
        .compile_protos(&["src/services/proto/service_registry/ServiceRegistry.proto"], &["src/services/proto"])
        .unwrap();
    Ok(())
}