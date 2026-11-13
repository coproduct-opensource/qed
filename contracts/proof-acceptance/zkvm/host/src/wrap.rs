//! The Groth16 step: a succinct receipt becomes the receipt and seal an
//! on-chain verifier takes.
//!
//! Two ways, chosen by `NUCLEUS_GROTH16`:
//!
//! - `native` (the default): `r0vm` re-proves the receipt over the BN254
//!   scalar field (`identity_p254`), and `nucleus-groth16-native` produces the
//!   Groth16 proof in this process from RISC Zero's published witness graph
//!   and proving key. Needs those two files; no container.
//! - `container`: RISC Zero's own path, which runs its x86 prover image
//!   through a `docker` on `PATH`.
//!
//! Either way the result is returned only after `risc0-zkvm` has verified it
//! as a Groth16 receipt for the expected image.
use risc0_zkvm::{
    default_prover,
    sha::{Digest, Digestible},
    ApiClient, Asset, AssetRequest, Groth16Receipt, Groth16ReceiptVerifierParameters, InnerReceipt,
    ProverOpts, Receipt,
};
use std::{error::Error, path::PathBuf};

pub const CHOICE_ENV: &str = "NUCLEUS_GROTH16";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Native,
    Container,
}

impl Choice {
    /// Unset means native. Anything but the two names is refused, so a typo
    /// cannot select a path silently.
    pub fn from_env() -> Result<Self, Box<dyn Error>> {
        match std::env::var(CHOICE_ENV) {
            Err(std::env::VarError::NotPresent) => Ok(Choice::Native),
            Err(error) => Err(error.into()),
            Ok(name) => Self::parse(&name),
        }
    }
    pub fn parse(name: &str) -> Result<Self, Box<dyn Error>> {
        match name {
            "native" => Ok(Choice::Native),
            "container" => Ok(Choice::Container),
            other => {
                Err(format!("{CHOICE_ENV} must be `native` or `container`, not `{other}`").into())
            }
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Choice::Native => "native",
            Choice::Container => "container",
        }
    }
}

/// `NUCLEUS_GROTH16_DATA`, or where `rzup install risc0-groth16` puts 0.2.0.
pub fn data_dir() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(dir) = std::env::var_os(nucleus_groth16_native::DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".risc0/extensions/v0.2.0-risc0-groth16"))
}

fn native(succinct: &Receipt) -> Result<Receipt, Box<dyn Error>> {
    let dir = data_dir()?;
    for file in [
        nucleus_groth16_native::GRAPH_FILE,
        nucleus_groth16_native::KEY_FILE,
    ] {
        if !dir.join(file).is_file() {
            return Err(format!(
                "{} is not in {}. Install RISC Zero's `risc0-groth16` 0.2.0 data (`rzup install risc0-groth16`), name its directory in {}, or set {CHOICE_ENV}=container",
                file,
                dir.display(),
                nucleus_groth16_native::DATA_DIR_ENV,
            )
            .into());
        }
    }
    let inner = succinct.inner.succinct()?;
    let identity = ApiClient::from_env()?.identity_p254(
        &ProverOpts::succinct(),
        Asset::try_from(inner.clone())?,
        AssetRequest::Inline,
    )?;
    let inputs = nucleus_groth16_native::inputs::from_seal(&identity.get_seal_bytes())?;
    let (proof, timing) = nucleus_groth16_native::wrap(&inputs, &dir)?;
    eprintln!(
        "native groth16: witness {:.1}s, quotient {:.1}s, key load and multiplications {:.1}s",
        timing.graph_load + timing.witness,
        timing.prove.quotient,
        timing.prove.load_and_multiply
    );
    Ok(Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt::new(
            proof.to_vec(),
            inner.claim.clone(),
            Groth16ReceiptVerifierParameters::default().digest(),
        )),
        succinct.journal.bytes.clone(),
    ))
}

/// Wrap, then verify the result for `image` before returning it.
pub fn groth16(
    choice: Choice,
    succinct: &Receipt,
    image: Digest,
) -> Result<Receipt, Box<dyn Error>> {
    let wrapped = match choice {
        Choice::Native => native(succinct)?,
        Choice::Container => default_prover().compress(&ProverOpts::groth16(), succinct)?,
    };
    wrapped.verify(image)?;
    Ok(wrapped)
}
