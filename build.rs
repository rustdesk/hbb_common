fn main() {
    println!("cargo:rerun-if-env-changed=RENDEZVOUS_SERVER");
    println!("cargo:rerun-if-env-changed=RS_PUB_KEY");
    println!("cargo:rerun-if-changed=protos/rendezvous.proto");

    let out_dir = format!("{}/protos", std::env::var("OUT_DIR").unwrap());

    std::fs::create_dir_all(&out_dir).unwrap();

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .inputs(["protos/rendezvous.proto"])
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run()
        .expect("Codegen failed.");
}
