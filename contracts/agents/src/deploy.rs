//! Deployment helpers: a progress file so an interrupted deployment resumes,
//! and deployment of runtime bytecode as given.
use crate::prelude::*;
use crate::*;

/// The library address baked into the FiatToken fixture, replaced at deploy.
const LINKED_LIBRARY: &str = "ba3b60c21e28c41df4babd90f228e1d368627da6";

/// Addresses of finished deployment steps, kept in a file beside the output.
pub struct Progress {
    pub path: std::path::PathBuf,
    pub chain_id: u64,
}
impl Progress {
    fn read(&self) -> serde_json::Value {
        fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .filter(|value| value["chainId"].as_u64() == Some(self.chain_id))
            .unwrap_or_else(|| serde_json::json!({"chainId": self.chain_id}))
    }
    /// Reuse the recorded address if code is still there; otherwise run the
    /// step and record its result.
    pub fn step(
        &self,
        chain: &Chain,
        name: &str,
        run: impl FnOnce() -> Res<Address>,
    ) -> Res<Address> {
        let mut state = self.read();
        if let Some(text) = state[name].as_str() {
            let address: Address = unhex(text)?
                .try_into()
                .map_err(|_| "recorded address length")?;
            if !chain.code(address)?.is_empty() {
                println!("  ok   {name}: already deployed at {}", hex(&address));
                return Ok(address);
            }
        }
        let address = run()?;
        state[name] = serde_json::json!(hex(&address));
        fs::write(&self.path, serde_json::to_vec_pretty(&state)?)?;
        Ok(address)
    }
}

/// An address already on the chain, or runtime bytecode to deploy.
pub fn existing_or_deploy(chain: &Chain, key: &SigningKey, spec: &str, what: &str) -> Res<Address> {
    let address = if spec.ends_with(".hex") {
        deploy(chain, key, &unhex(fs::read_to_string(spec)?.trim())?, what)?
    } else {
        unhex(spec)?
            .try_into()
            .map_err(|_| format!("{what}: not an address"))?
    };
    let code = chain.code(address)?;
    if code.is_empty() {
        return Err(format!("{what}: no contract at {}", hex(&address)).into());
    }
    println!(
        "  ok   {what} at {}: {} bytes, code hash {}",
        hex(&address),
        code.len(),
        hex(&keccak(&code))
    );
    Ok(address)
}

/// Init code that returns `runtime` unchanged.
fn init_code(runtime: &[u8]) -> Vec<u8> {
    let mut code = vec![0x7f];
    code.extend_from_slice(&U256::from(runtime.len()).to_be_bytes::<32>());
    code.extend_from_slice(&[0x80, 0x60, 0x2b, 0x60, 0x00, 0x39, 0x60, 0x00, 0xf3, 0x00]);
    code.extend_from_slice(runtime);
    code
}
fn deploy(chain: &Chain, dev: &SigningKey, runtime: &[u8], what: &str) -> Res<Address> {
    let receipt = chain.send(dev, None, 0, &init_code(runtime))?;
    let address = receipt
        .contract
        .filter(|_| receipt.success)
        .ok_or(format!("{what}: deployment failed"))?;
    if chain.code(address)? != runtime {
        return Err(format!("{what}: deployed code differs from the bytes sent").into());
    }
    println!(
        "  ok   deploy {what}: {} ({} bytes) gas {}",
        hex(&address),
        runtime.len(),
        receipt.gas_used
    );
    Ok(address)
}

/// Deploy real FiatToken bytecode with its signature library relinked, and
/// initialise it with `dev` as owner and minter.
pub fn deploy_token(
    chain: &Chain,
    dev: &SigningKey,
    token_hex: &str,
    library: Address,
) -> Res<Address> {
    let dev_address = address_of(dev);
    println!("token: FiatToken bytecode with its signature library relinked");
    let linked = fs::read_to_string(token_hex)?
        .trim()
        .replace(LINKED_LIBRARY, hex(&library).trim_start_matches("0x"));
    let token = deploy(chain, dev, &unhex(&linked)?, "token")?;
    let admin = A::from(dev_address);
    for (data, what) in [
        (
            initializeCall {
                tokenName: "USDC".into(),
                tokenSymbol: "USDC".into(),
                tokenCurrency: "USD".into(),
                tokenDecimals: 6,
                newMasterMinter: admin,
                newPauser: admin,
                newBlacklister: admin,
                newOwner: admin,
            }
            .abi_encode(),
            "initialize",
        ),
        (
            initializeV2Call {
                newName: "USDC".into(),
            }
            .abi_encode(),
            "initializeV2",
        ),
        (
            initializeV2_1Call {
                lostAndFound: admin,
            }
            .abi_encode(),
            "initializeV2_1",
        ),
        (
            initializeV2_2Call {
                accountsToBlacklist: vec![],
                newSymbol: "USDC".into(),
            }
            .abi_encode(),
            "initializeV2_2",
        ),
        (
            configureMinterCall {
                minter: admin,
                minterAllowedAmount: U256::from(u64::MAX),
            }
            .abi_encode(),
            "configureMinter",
        ),
    ] {
        if !chain.send(dev, Some(token), 0, &data)?.success {
            return Err(format!("token {what} reverted").into());
        }
    }

    Ok(token)
}
