//! What the agents share: key files, the policy's JSON form, and the call out
//! to the zero-knowledge prover.
use crate::chain::{Address, Res, address_of, hex, unhex};
use crate::dpop::dpop_binding_of;
use k256::ecdsa::SigningKey;
use nucleus_proof_acceptance::Policy;
use serde_json::{Value, json};
use std::{fs, io::Read, path::Path, process::Command};

pub const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn random32() -> Res<[u8; 32]> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// One agent's keys: a secp256k1 wallet, a P-256 possession key for DPoP, and
/// an Ed25519 key that is the agent's iroh node identity. One hex key per
/// line, in that order. A file written before the node key existed has two
/// lines; the third is appended on first use.
pub struct Keys {
    pub wallet: SigningKey,
    pub possession: p256::ecdsa::SigningKey,
    pub node: [u8; 32],
}
impl Keys {
    /// Load the key file, creating it with fresh random keys if it is absent.
    /// The file is readable by its owner only.
    pub fn load_or_create(path: &str) -> Res<Self> {
        use std::os::unix::fs::PermissionsExt;
        let private = fs::Permissions::from_mode(0o600);
        if !Path::new(path).exists() {
            let text = format!(
                "{}\n{}\n{}\n",
                hex(&random32()?),
                hex(&random32()?),
                hex(&random32()?)
            );
            // Create the file private before any key is written to it.
            fs::write(path, "")?;
            fs::set_permissions(path, private.clone())?;
            fs::write(path, text)?;
        }
        let mut text = fs::read_to_string(path)?;
        if text.lines().count() == 2 {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!("{}\n", hex(&random32()?)));
            fs::write(path, &text)?;
        }
        fs::set_permissions(path, private)?;
        let mut lines = text.lines();
        let wallet = unhex(lines.next().ok_or("wallet key missing")?)?;
        let possession = unhex(lines.next().ok_or("possession key missing")?)?;
        let node: [u8; 32] = unhex(lines.next().ok_or("node key missing")?)?
            .try_into()
            .map_err(|_| "node key length")?;
        Ok(Self {
            wallet: SigningKey::from_slice(&wallet)?,
            possession: p256::ecdsa::SigningKey::from_slice(&possession)?,
            node,
        })
    }
    pub fn address(&self) -> Address {
        address_of(&self.wallet)
    }
    pub fn binding(&self) -> [u8; 32] {
        dpop_binding_of(&self.possession)
    }
}

pub fn policy_json(policy: &Policy) -> Value {
    json!({
        "statementSha256": hex(&policy.statement_sha256), "claim": policy.claim,
        "permittedAxioms": policy.permitted_axioms, "maximumArtifactBytes": policy.maximum_artifact_bytes,
    })
}
pub fn policy_from(value: &Value) -> Res<Policy> {
    Ok(Policy {
        statement_sha256: unhex(
            value["statementSha256"]
                .as_str()
                .ok_or("statementSha256 missing")?,
        )?
        .try_into()
        .map_err(|_| "statement hash length")?,
        claim: value["claim"].as_str().ok_or("claim missing")?.to_owned(),
        permitted_axioms: value["permittedAxioms"]
            .as_array()
            .ok_or("permittedAxioms missing")?
            .iter()
            .map(|a| a.as_str().map(str::to_owned).ok_or("axiom name expected"))
            .collect::<Result<_, _>>()?,
        maximum_artifact_bytes: u32::try_from(
            value["maximumArtifactBytes"]
                .as_u64()
                .ok_or("size limit missing")?,
        )?,
    })
}

/// How the last step of a settlement proof, the Groth16 wrap, is done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Groth16 {
    /// In the prover host's own process, in Rust. `data` names the directory
    /// holding RISC Zero's `risc0-groth16` 0.2.0 files; absent, the host looks
    /// where `rzup` installs them.
    Native { data: Option<String> },
    /// RISC Zero's x86 prover image, run by the `docker` found in this
    /// directory.
    Container { docker_dir: String },
}
impl Groth16 {
    /// From a seller's configuration: `groth16` is `native` (the default) or
    /// `container`. A container needs `dockerDir`; a name that is neither is
    /// refused, so a typo cannot pick a path.
    pub fn from_config(
        choice: Option<&str>,
        data: Option<String>,
        docker_dir: Option<String>,
    ) -> Res<Self> {
        match choice {
            None | Some("native") => Ok(Groth16::Native { data }),
            Some("container") => Ok(Groth16::Container {
                docker_dir: docker_dir.ok_or("groth16 is `container` but dockerDir is missing")?,
            }),
            Some(other) => {
                Err(format!("groth16 must be `native` or `container`, not `{other}`").into())
            }
        }
    }
    /// The environment the prover host reads the choice from.
    fn apply(&self, command: &mut Command) {
        match self {
            Groth16::Native { data } => {
                command.env("NUCLEUS_GROTH16", "native");
                if let Some(data) = data {
                    command.env("NUCLEUS_GROTH16_DATA", data);
                }
            }
            Groth16::Container { docker_dir } => {
                command.env("NUCLEUS_GROTH16", "container").env(
                    "PATH",
                    format!("{docker_dir}:{}", std::env::var("PATH").unwrap_or_default()),
                );
            }
        }
    }
}

/// A checked base library this seller builds on. When a statement begins with
/// exactly these bytes the seller names the base in its order, proves on the
/// base program's receipt, and the base's registered payee is owed the royalty
/// out of the seller's share.
#[derive(Clone)]
pub struct BaseOffer {
    pub bytes: std::sync::Arc<Vec<u8>>,
    /// SHA-256 of `bytes`.
    pub id: [u8; 32],
    /// The base program's succinct receipt for this base.
    pub receipt: std::path::PathBuf,
    /// Payee and rate that receipt commits.
    pub payee: Address,
    pub bps: u16,
}

/// Which published third-form order program a seller proves with. The
/// program is part of every order (its image ID), so a seller's choice must
/// match the deployment and the posts it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ThirdProgram {
    /// Statement format v2 (`program/nucleus-order-fmt2.bin`, bases from
    /// `nucleus-base-check-fmt2.bin`): the default since the redeployment
    /// of 2026-11-13.
    #[default]
    FormatV2,
    /// The earlier pair (`nucleus-vault3-acceptance.bin`,
    /// `nucleus-base-check.bin`), still named by the deployment of
    /// 2026-11-12 and its posted tasks.
    Earlier,
}
impl ThirdProgram {
    /// From a seller config's `proofProgram`: absent or `"fmt2"` for format
    /// v2, `"vault3"` for the earlier program. Anything else is refused.
    pub fn from_config(value: Option<&str>) -> Res<Self> {
        match value {
            None | Some("fmt2") => Ok(Self::FormatV2),
            Some("vault3") => Ok(Self::Earlier),
            Some(other) => {
                Err(format!("proofProgram {other:?}: expected \"fmt2\" or \"vault3\"").into())
            }
        }
    }
}

/// Where to find the zero-knowledge prover.
#[derive(Clone)]
pub struct RealProofs {
    pub host: String,
    pub groth16: Groth16,
    pub out: std::path::PathBuf,
    pub third: ThirdProgram,
}
impl RealProofs {
    /// The host's command prefix for the program that proves orders of a
    /// vault of this form.
    fn prefix(&self, form: nucleus_proof_commerce::vault::Form) -> &'static str {
        match (form, self.third) {
            (nucleus_proof_commerce::vault::Form::Second, _) => "vault-",
            // The base-aware programs: they also prove orders that name no base.
            (nucleus_proof_commerce::vault::Form::Third, ThirdProgram::FormatV2) => "order2-",
            (nucleus_proof_commerce::vault::Form::Third, ThirdProgram::Earlier) => "vault3-",
        }
    }
    /// The image ID of the program the host carries for this form of vault.
    pub fn program(&self, form: nucleus_proof_commerce::vault::Form) -> Res<[u8; 32]> {
        let image = Command::new(&self.host)
            .arg(format!("{}image", self.prefix(form)))
            .output()?;
        if !image.status.success() {
            return Err("the prover host did not report an image id".into());
        }
        unhex(
            String::from_utf8(image.stdout)?
                .split_whitespace()
                .nth(1)
                .ok_or("host printed no image id")?,
        )?
        .try_into()
        .map_err(|_| "image id length".into())
    }
    /// Prove `input` with the vault guest, wrap to Groth16, and return the
    /// 260-byte seal. Fails if the guest refuses the input.
    pub fn seal(
        &self,
        form: nucleus_proof_commerce::vault::Form,
        name: &str,
        input: &[u8],
        base_receipt: Option<&Path>,
    ) -> Res<Vec<u8>> {
        let (prove, wrap) = (
            format!("{}prove", self.prefix(form)),
            format!("{}groth16", self.prefix(form)),
        );
        fs::create_dir_all(&self.out)?;
        let path = |ext: &str| self.out.join(format!("{name}.{ext}"));
        fs::write(path("input"), input)?;
        let started = std::time::Instant::now();
        let run = |args: &[&std::ffi::OsStr]| -> Res<()> {
            let work = self.out.join(format!("{name}.groth16-work"));
            fs::create_dir_all(&work)?;
            let mut command = Command::new(&self.host);
            command.args(args).env("RISC0_WORK_DIR", &work);
            self.groth16.apply(&mut command);
            let output = command.output()?;
            if !output.status.success() {
                return Err(
                    format!("{name}: {}", String::from_utf8_lossy(&output.stderr).trim()).into(),
                );
            }
            Ok(())
        };
        let (input_path, receipt, wrapped, seal) = (
            path("input"),
            path("receipt"),
            path("groth16.receipt"),
            path("seal.hex"),
        );
        // An order that names a base is proved on the base program's receipt.
        match base_receipt {
            None => run(&[prove.as_ref(), input_path.as_os_str(), receipt.as_os_str()])?,
            Some(base) => run(&[
                prove.as_ref(),
                input_path.as_os_str(),
                receipt.as_os_str(),
                base.as_os_str(),
            ])?,
        }
        run(&[
            wrap.as_ref(),
            receipt.as_os_str(),
            wrapped.as_os_str(),
            seal.as_os_str(),
        ])?;
        let seal = unhex(fs::read_to_string(seal)?.trim())?;
        println!(
            "  ok   proved {name}: {} byte seal in {:.0} s",
            seal.len(),
            started.elapsed().as_secs_f64()
        );
        Ok(seal)
    }
}

/// `keys KEYFILE` prints the wallet address, creating the file if absent.
pub fn keys(args: &[String]) -> Res<()> {
    let [keyfile] = args else {
        return Err("usage: keys KEYFILE".into());
    };
    let keys = Keys::load_or_create(keyfile)?;
    println!("{}", hex(&keys.address()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Groth16, RealProofs, ThirdProgram};

    #[test]
    fn the_groth16_choice_is_native_unless_a_container_is_named_and_a_typo_is_refused() {
        assert_eq!(
            Groth16::from_config(None, None, Some("/d".into())).unwrap(),
            Groth16::Native { data: None }
        );
        assert_eq!(
            Groth16::from_config(Some("native"), Some("/data".into()), None).unwrap(),
            Groth16::Native {
                data: Some("/data".into())
            }
        );
        assert_eq!(
            Groth16::from_config(Some("container"), None, Some("/d".into())).unwrap(),
            Groth16::Container {
                docker_dir: "/d".into()
            }
        );
        assert!(Groth16::from_config(Some("container"), None, None).is_err());
        assert!(Groth16::from_config(Some("contaner"), None, Some("/d".into())).is_err());
    }

    /// The third-form program defaults to statement format v2; the earlier
    /// one is chosen by name; a misspelling is refused, not defaulted.
    #[test]
    fn the_third_form_program_is_chosen_by_name_and_defaults_to_format_v2() {
        let proofs = |third| RealProofs {
            host: String::new(),
            groth16: Groth16::Native { data: None },
            out: std::path::PathBuf::new(),
            third,
        };
        use nucleus_proof_commerce::vault::Form;
        assert_eq!(
            ThirdProgram::from_config(None).unwrap(),
            ThirdProgram::FormatV2
        );
        assert_eq!(
            ThirdProgram::from_config(Some("fmt2")).unwrap(),
            ThirdProgram::FormatV2
        );
        assert_eq!(
            ThirdProgram::from_config(Some("vault3")).unwrap(),
            ThirdProgram::Earlier
        );
        assert!(ThirdProgram::from_config(Some("vault-3")).is_err());
        assert_eq!(
            proofs(ThirdProgram::FormatV2).prefix(Form::Third),
            "order2-"
        );
        assert_eq!(proofs(ThirdProgram::Earlier).prefix(Form::Third), "vault3-");
        assert_eq!(
            proofs(ThirdProgram::FormatV2).prefix(Form::Second),
            "vault-"
        );
    }
}
