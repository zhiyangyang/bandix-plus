use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // Allow unit tests / cargo check without a full eBPF toolchain.
    if std::env::var_os("AYA_BUILD_SKIP").is_some() {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        std::fs::create_dir_all(&out_dir)?;
        let stub = out_dir.join("bandix-plus");
        if !stub.exists() {
            std::fs::write(&stub, b"")?;
        }
        println!("cargo:warning=AYA_BUILD_SKIP=1; using stub eBPF object");
        return Ok(());
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "bandix-plus-ebpf")
        .ok_or_else(|| anyhow!("bandix-plus-ebpf package not found"))?;
    let cargo_metadata::Package { name, manifest_path, .. } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
