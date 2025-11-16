use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("IDALIB_FORCE_STUB_LINKAGE").is_ok() {
        idalib_build::configure_idasdk_linkage();

        #[cfg(target_os = "linux")]
        {
            let (_, stub_path, _, _) = idalib_build::idalib_sdk_paths();
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-l:libida.so",
                stub_path.display(),
                stub_path.display(),
            );
            println!(
                "cargo::rustc-link-arg=-Wl,-rpath,{},-L{},-l:libidalib.so",
                stub_path.display(),
                stub_path.display(),
            );
        }
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
