//! Operations on a deployment: deploy, prepare a test chain, preflight, sweep
//! fees, move gas money, swap native currency for a token.
//!
//!   deploy    RPC KEYFILE VAULT_BIN VERIFIER TOKEN LIBRARY TREASURY OUT_DIR
//!   prepare   DEPLOYMENT KEYFILE BUYER_ADDRESS SELLER_ADDRESS SELLER_GAS_WEI
//!   preflight RPC VERIFIER_ADDRESS VERIFIER_RUNTIME_HEX TOKEN_ADDRESS PAYER_ADDRESS VAULT_BIN
//!   sweep     DEPLOYMENT KEYFILE
//!   send-gas  RPC KEYFILE TO_ADDRESS WEI
//!   swap-native RPC KEYFILE ROUTER FACTORY WRAPPED TOKEN FEE RECIPIENT WEI_IN [send MINIMUM_OUT]
//!   keys      KEYFILE
//!
//! VERIFIER, TOKEN and LIBRARY are each a 0x address already on the chain or a
//! `.hex` file of runtime bytecode to deploy. TREASURY is a 0x address, or the
//! word `test-key` to make a key file in OUT_DIR (test chains only). The
//! deployer's wallet must be the token's minter for `prepare` to work (true of
//! a token this tool deployed; not of a real stablecoin).
use crate::deploy::deploy_token;
use crate::mintCall;
use crate::prelude::*;
use crate::world::*;

/// What `prepare` mints to the buyer on a test chain.
const TASK_PRICE: u64 = 1_000_000;

pub fn deploy(args: &[String]) -> Res<()> {
    let [
        rpc,
        keyfile,
        vault_bin,
        verifier,
        token,
        library,
        treasury,
        out,
    ] = args
    else {
        return Err(
            "usage: vault-deploy RPC KEYFILE VAULT_BIN VERIFIER TOKEN LIBRARY TREASURY OUT_DIR"
                .into(),
        );
    };
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let before = chain.balance(address_of(&payer))?;
    println!(
        "chain {} payer {} balance {} wei",
        chain.id,
        hex(&address_of(&payer)),
        before
    );
    let out = Path::new(out);
    fs::create_dir_all(out)?;
    let progress = crate::deploy::Progress {
        path: out.join("vault-progress.json"),
        chain_id: chain.id,
    };
    let verifier = progress.step(&chain, "verifier", || {
        crate::deploy::existing_or_deploy(&chain, &payer, verifier, "proof verifier")
    })?;
    let token = if token.ends_with(".hex") {
        let library = progress.step(&chain, "library", || {
            crate::deploy::existing_or_deploy(&chain, &payer, library, "signature library")
        })?;
        progress.step(&chain, "token", || {
            deploy_token(&chain, &payer, token, library)
        })?
    } else {
        progress.step(&chain, "token", || {
            crate::deploy::existing_or_deploy(&chain, &payer, token, "token")
        })?
    };
    // The treasury is fixed forever and receives every fee, so it is named by
    // whoever deploys. A key file made here is for test chains only and must
    // be asked for by name.
    let treasury = if treasury == "test-key" {
        Keys::load_or_create(out.join("treasury.keys").to_str().ok_or("path")?)?.address()
    } else {
        let address = address_arg(treasury)?;
        if address == [0; 20] {
            return Err("treasury is the zero address".into());
        }
        address
    };
    let vault = progress.step(&chain, "vault", || {
        let constructor = (A::from(treasury), FEE_BPS, MAXIMUM_FEE_BPS).abi_encode();
        let code = [unhex(fs::read_to_string(vault_bin)?.trim())?, constructor].concat();
        let receipt = chain.send(&payer, None, 0, &code)?;
        let address = receipt
            .contract
            .filter(|_| receipt.success)
            .ok_or("vault deployment failed")?;
        println!(
            "  ok   deploy vault: {} in tx {} gas {}",
            hex(&address),
            receipt.transaction,
            receipt.gas_used
        );
        Ok(address)
    })?;
    let code = chain.code(vault)?;
    println!(
        "  ok   vault {}: {} bytes, code hash {}; treasury {}",
        hex(&vault),
        code.len(),
        hex(&keccak(&code)),
        hex(&treasury)
    );
    fs::write(
        out.join("vault-deployment.json"),
        serde_json::to_vec_pretty(&json!({
            "rpc": rpc, "chainId": chain.id, "vault": hex(&vault), "token": hex(&token),
            "verifier": hex(&verifier), "treasury": hex(&treasury),
        }))?,
    )?;
    println!(
        "payer spent {} wei",
        before.saturating_sub(chain.balance(address_of(&payer))?)
    );
    Ok(())
}

pub fn prepare(args: &[String]) -> Res<()> {
    let [deployment, keyfile, buyer, seller, gas] = args else {
        return Err(
            "usage: vault-prepare DEPLOYMENT KEYFILE BUYER_ADDRESS SELLER_ADDRESS SELLER_GAS_WEI"
                .into(),
        );
    };
    let world = World::read(deployment)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let (buyer, seller) = (address_arg(buyer)?, address_arg(seller)?);
    let minted = world.chain.send(
        &payer,
        Some(world.token),
        0,
        &mintCall {
            to: A::from(buyer),
            amount: U256::from(TASK_PRICE),
        }
        .abi_encode(),
    )?;
    println!(
        "  {} mint {TASK_PRICE} to buyer {}: tx {}",
        if minted.success { "ok  " } else { "FAIL" },
        hex(&buyer),
        minted.transaction
    );
    let funded = world.chain.send(&payer, Some(seller), gas.parse()?, &[])?;
    println!(
        "  {} {gas} wei of gas money to seller {}: tx {}",
        if funded.success { "ok  " } else { "FAIL" },
        hex(&seller),
        funded.transaction
    );
    if minted.success && funded.success {
        Ok(())
    } else {
        Err("preparation failed".into())
    }
}

/// Read-only check of a chain before a deployment: is the expected proof
/// verifier there, how does the token sign, and what does gas cost. Sends
/// nothing.
///
///   vault-preflight RPC VERIFIER_ADDRESS VERIFIER_RUNTIME_HEX TOKEN_ADDRESS PAYER_ADDRESS VAULT_BIN
pub fn preflight(args: &[String]) -> Res<()> {
    let [rpc, verifier, expected, token, payer, vault_bin] = args else {
        return Err(
            "usage: vault-preflight RPC VERIFIER_ADDRESS VERIFIER_RUNTIME_HEX TOKEN_ADDRESS PAYER_ADDRESS VAULT_BIN"
                .into(),
        );
    };
    let chain = Chain::connect(rpc)?;
    println!("chain {}", chain.id);
    let code = chain.code(address_arg(verifier)?)?;
    let expected = unhex(fs::read_to_string(expected)?.trim())?;
    println!(
        "verifier {verifier}: {} bytes, code hash {}",
        code.len(),
        hex(&keccak(&code))
    );
    if code != expected {
        return Err("verifier code differs from the expected runtime".into());
    }
    println!("  ok   verifier code equals the expected runtime");
    let token = address_arg(token)?;
    let domain = token_domain(&chain, token)?;
    println!(
        "token {}: signs as name {:?} version {:?}",
        hex(&token),
        domain.name,
        domain.version
    );
    let price = u128::from_str_radix(
        chain
            .rpc("eth_gasPrice", json!([]))?
            .as_str()
            .ok_or("gas price")?
            .trim_start_matches("0x"),
        16,
    )?;
    let init = unhex(fs::read_to_string(vault_bin)?.trim())?;
    // Creation costs 32,000 plus 200 per byte of runtime plus calldata and
    // constructor execution; 2,000,000 is a ceiling for a 5.5 KB contract.
    let ceiling = 2_000_000u128;
    println!(
        "gas price {price} wei; vault creation code {} bytes; at most {} wei for deployment",
        init.len(),
        price * ceiling
    );
    let balance = chain.balance(address_arg(payer)?)?;
    println!("payer {payer} balance {balance} wei");
    if balance < price * ceiling {
        println!("  need payer balance is below the deployment ceiling");
    }
    Ok(())
}

/// Send the fees a second-form vault has booked in the deployment's token to
/// its treasury. Any wallet may do this; the caller only pays gas.
///
///   vault-sweep DEPLOYMENT KEYFILE
pub fn sweep(args: &[String]) -> Res<()> {
    let [deployment, keyfile] = args else {
        return Err("usage: vault-sweep DEPLOYMENT KEYFILE".into());
    };
    let world = World::read(deployment)?;
    if world.deployment.rules.form() != vault::Form::Second {
        return Err("this deployment is a third-form vault: use claim".into());
    }
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let vault = world.deployment.vault;
    let token_word = [&[0u8; 12][..], &world.token[..]].concat();
    // accrued(address) and sweep(address)
    let selector = |signature: &str| keccak(signature.as_bytes())[..4].to_vec();
    let accrued = U256::from_be_slice(&world.chain.call(
        [0; 20],
        vault,
        &[selector("accrued(address)"), token_word.clone()].concat(),
    )?);
    let treasury = world.deployment.treasury;
    let before = world.balance(treasury)?;
    println!(
        "vault {} has booked {accrued} in token {}; treasury {} holds {before}",
        hex(&vault),
        hex(&world.token),
        hex(&treasury)
    );
    if accrued.is_zero() {
        return Err("nothing accrued".into());
    }
    let receipt = world.chain.send(
        &payer,
        Some(vault),
        0,
        &[selector("sweep(address)"), token_word].concat(),
    )?;
    let after = world.balance(treasury)?;
    println!(
        "  {} sweep: tx {} gas {}; treasury {before} -> {after}",
        if receipt.success { "ok  " } else { "FAIL" },
        receipt.transaction,
        receipt.gas_used
    );
    if receipt.success && after - before == accrued {
        Ok(())
    } else {
        Err("sweep did not deliver the booked amount".into())
    }
}

/// Send native currency from one of our wallets to an address, for gas.
///
///   send-gas RPC KEYFILE TO_ADDRESS WEI
pub fn send_gas(args: &[String]) -> Res<()> {
    let [rpc, keyfile, to, wei] = args else {
        return Err("usage: send-gas RPC KEYFILE TO_ADDRESS WEI".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let to = address_arg(to)?;
    let receipt = chain.send(&payer, Some(to), wei.parse()?, &[])?;
    println!(
        "  {} chain {} sent {wei} wei from {} to {}: tx {}; recipient now holds {} wei",
        if receipt.success { "ok  " } else { "FAIL" },
        chain.id,
        hex(&address_of(&payer)),
        hex(&to),
        receipt.transaction,
        chain.balance(to)?
    );
    if receipt.success {
        Ok(())
    } else {
        Err("transfer failed".into())
    }
}

/// The ERC-20 `transfer(to, amount)` call.
pub fn token_transfer_call(to: Address, amount: U256) -> Vec<u8> {
    sol! {
        function transfer(address to, uint256 amount) returns (bool);
    }
    transferCall {
        to: A::from(to),
        amount,
    }
    .abi_encode()
}

/// Send tokens from one of our wallets to an address: a plain ERC-20
/// transfer, checked by the balances on both sides before and after.
///
///   send-token RPC KEYFILE TOKEN TO_ADDRESS UNITS
pub fn send_token(args: &[String]) -> Res<()> {
    let [rpc, keyfile, token, to, units] = args else {
        return Err("usage: send-token RPC KEYFILE TOKEN TO_ADDRESS UNITS".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let (token, to, from) = (address_arg(token)?, address_arg(to)?, address_of(&payer));
    let units = U256::from(units.parse::<u128>()?);
    if to == from || to == [0; 20] {
        return Err("recipient is the sender or the zero address".into());
    }
    let held = |owner: Address| -> Res<U256> {
        Ok(U256::from_be_slice(
            &chain.call(
                owner,
                token,
                &crate::balanceOfCall {
                    account: A::from(owner),
                }
                .abi_encode(),
            )?,
        ))
    };
    let (sender_before, recipient_before) = (held(from)?, held(to)?);
    if sender_before < units {
        return Err(format!("sender holds {sender_before}, less than {units}").into());
    }
    let receipt = chain.send(&payer, Some(token), 0, &token_transfer_call(to, units))?;
    let (sender_after, recipient_after) = (held(from)?, held(to)?);
    println!(
        "  {} chain {} token {}: {units} from {} to {}: tx {} gas {}; sender {sender_before} -> {sender_after}, recipient {recipient_before} -> {recipient_after}",
        if receipt.success { "ok  " } else { "FAIL" },
        chain.id,
        hex(&token),
        hex(&from),
        hex(&to),
        receipt.transaction,
        receipt.gas_used
    );
    if receipt.success
        && sender_before - sender_after == units
        && recipient_after - recipient_before == units
    {
        Ok(())
    } else {
        Err("the transfer did not move exactly the amount".into())
    }
}

sol! {
    struct ExactInputSingleParams { address tokenIn; address tokenOut; uint24 fee; address recipient; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96; }
    function exactInputSingle(ExactInputSingleParams params) returns (uint256 amountOut);
    function factory() returns (address);
    function WETH9() returns (address);
    function getPool(address a, address b, uint24 fee) returns (address);
}

/// Swap native currency for a token through a Uniswap v3 SwapRouter02, paying
/// the token to RECIPIENT. Without `send MINIMUM_OUT` it only checks the
/// router and reports what the swap would return.
///
///   swap-native RPC KEYFILE ROUTER FACTORY WRAPPED TOKEN FEE RECIPIENT WEI_IN [send MINIMUM_OUT]
pub fn swap_native(args: &[String]) -> Res<()> {
    let [
        rpc,
        keyfile,
        router,
        factory,
        wrapped,
        token,
        fee,
        recipient,
        wei,
        apply @ ..,
    ] = args
    else {
        return Err("usage: swap-native RPC KEYFILE ROUTER FACTORY WRAPPED TOKEN FEE RECIPIENT WEI_IN [send MINIMUM_OUT]".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let from = address_of(&payer);
    let (router, factory, wrapped, token, recipient) = (
        address_arg(router)?,
        address_arg(factory)?,
        address_arg(wrapped)?,
        address_arg(token)?,
        address_arg(recipient)?,
    );
    let fee: u32 = fee.parse()?;
    let wei: u128 = wei.parse()?;
    // The router must be the one that belongs to the expected factory and
    // wrapped token, and the pool must exist.
    let reported = |data: Vec<u8>| -> Res<Address> {
        chain.call(from, router, &data)?[12..]
            .try_into()
            .map_err(|_| "address reply".into())
    };
    if reported(factoryCall {}.abi_encode())? != factory {
        return Err("router reports a different factory".into());
    }
    if reported(WETH9Call {}.abi_encode())? != wrapped {
        return Err("router reports a different wrapped token".into());
    }
    let pool: Address = chain.call(
        from,
        factory,
        &getPoolCall {
            a: A::from(wrapped),
            b: A::from(token),
            fee: alloy_primitives::aliases::U24::from(fee),
        }
        .abi_encode(),
    )?[12..]
        .try_into()
        .map_err(|_| "pool reply")?;
    if pool == [0; 20] || chain.code(pool)?.is_empty() {
        return Err("no pool for this pair and fee".into());
    }
    let call = |minimum: U256| {
        exactInputSingleCall {
            params: ExactInputSingleParams {
                tokenIn: A::from(wrapped),
                tokenOut: A::from(token),
                fee: alloy_primitives::aliases::U24::from(fee),
                recipient: A::from(recipient),
                amountIn: U256::from(wei),
                amountOutMinimum: minimum,
                sqrtPriceLimitX96: Default::default(),
            },
        }
        .abi_encode()
    };
    println!(
        "chain {} router {} pool {}; payer {} holds {} wei",
        chain.id,
        hex(&router),
        hex(&pool),
        hex(&from),
        chain.balance(from)?
    );
    let quote = chain.rpc(
        "eth_call",
        json!([{"from": hex(&from), "to": hex(&router), "value": format!("0x{wei:x}"), "data": hex(&call(U256::ZERO))}, "latest"]),
    )?;
    let quoted = U256::from_be_slice(&unhex(quote.as_str().ok_or("quote reply")?)?);
    println!("  {wei} wei would buy {quoted} units of {}", hex(&token));
    let [word, minimum] = apply else {
        return Ok(());
    };
    if word != "send" {
        return Err("expected `send MINIMUM_OUT`".into());
    }
    let minimum = U256::from(minimum.parse::<u128>()?);
    if quoted < minimum {
        return Err("quote is below the minimum".into());
    }
    let receipt = chain.send(&payer, Some(router), wei, &call(minimum))?;
    println!(
        "  {} swap: tx {} gas {}",
        if receipt.success { "ok  " } else { "FAIL" },
        receipt.transaction,
        receipt.gas_used
    );
    if receipt.success {
        Ok(())
    } else {
        Err("swap failed".into())
    }
}

/// Deploy a task board for an existing vault. The board is immutable and
/// names that vault forever.
///
///   board-deploy RPC KEYFILE BOARD_BIN VAULT_ADDRESS OUT_JSON
pub fn board_deploy(args: &[String]) -> Res<()> {
    let [rpc, keyfile, board_bin, vault_address, out] = args else {
        return Err("usage: board-deploy RPC KEYFILE BOARD_BIN VAULT_ADDRESS OUT_JSON".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let vault_address = address_arg(vault_address)?;
    if chain.code(vault_address)?.is_empty() {
        return Err("there is no contract at the vault address".into());
    }
    let mut code = unhex(fs::read_to_string(board_bin)?.trim())?;
    code.extend_from_slice(&[0u8; 12]);
    code.extend_from_slice(&vault_address);
    let receipt = chain.send(&payer, None, 0, &code)?;
    let address = receipt
        .contract
        .filter(|_| receipt.success)
        .ok_or("board deployment failed")?;
    let board = crate::board::Board {
        chain: chain.clone(),
        address,
    };
    if board.vault()? != vault_address {
        return Err("the deployed board names another vault".into());
    }
    let runtime = chain.code(address)?;
    println!(
        "  ok   chain {} board {} for vault {} in tx {} gas {}; {} bytes, code hash {}",
        chain.id,
        hex(&address),
        hex(&vault_address),
        receipt.transaction,
        receipt.gas_used,
        runtime.len(),
        hex(&keccak(&runtime))
    );
    fs::write(
        out,
        serde_json::to_vec_pretty(&json!({
            "rpc": rpc, "chainId": chain.id, "board": hex(&address), "vault": hex(&vault_address),
            "deployTransaction": receipt.transaction,
        }))?,
    )?;
    Ok(())
}

/// Deploy a third-form vault (NucleusVault3) for an existing verifier and
/// token. REGISTRY is a 0x address already on the chain, or a `.hex` file of
/// runtime bytecode to deploy (the empty registry's, for now). TREASURY is a
/// 0x address, or the word `test-key` to make a key file in OUT_DIR (test
/// chains only). The fee is 25 basis points with a 100 basis point cap.
///
///   deploy3 RPC KEYFILE VAULT3_BIN REGISTRY VERIFIER TOKEN TREASURY MAXIMUM_TERM_SECONDS OUT_DIR
pub fn deploy3(args: &[String]) -> Res<()> {
    let [
        rpc,
        keyfile,
        vault_bin,
        registry,
        verifier,
        token,
        treasury,
        term,
        out,
    ] = args
    else {
        return Err("usage: deploy3 RPC KEYFILE VAULT3_BIN REGISTRY VERIFIER TOKEN TREASURY MAXIMUM_TERM_SECONDS OUT_DIR".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let term: u64 = term.parse()?;
    if term == 0 {
        return Err("the maximum term must be positive".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let before = chain.balance(address_of(&payer))?;
    println!(
        "chain {} payer {} balance {} wei",
        chain.id,
        hex(&address_of(&payer)),
        before
    );
    let out = Path::new(out);
    fs::create_dir_all(out)?;
    let progress = crate::deploy::Progress {
        path: out.join("vault-progress.json"),
        chain_id: chain.id,
    };
    let verifier = progress.step(&chain, "verifier", || {
        crate::deploy::existing_or_deploy(&chain, &payer, verifier, "proof verifier")
    })?;
    let token = progress.step(&chain, "token", || {
        crate::deploy::existing_or_deploy(&chain, &payer, token, "token")
    })?;
    let registry = progress.step(&chain, "registry", || {
        crate::deploy::existing_or_deploy(&chain, &payer, registry, "base registry")
    })?;
    let treasury = if treasury == "test-key" {
        Keys::load_or_create(out.join("treasury.keys").to_str().ok_or("path")?)?.address()
    } else {
        let address = address_arg(treasury)?;
        if address == [0; 20] {
            return Err("treasury is the zero address".into());
        }
        address
    };
    let vault = progress.step(&chain, "vault", || {
        let constructor = (
            A::from(treasury),
            FEE_BPS,
            MAXIMUM_FEE_BPS,
            term,
            A::from(registry),
        )
            .abi_encode();
        let code = [unhex(fs::read_to_string(vault_bin)?.trim())?, constructor].concat();
        let receipt = chain.send(&payer, None, 0, &code)?;
        let address = receipt
            .contract
            .filter(|_| receipt.success)
            .ok_or("vault deployment failed")?;
        println!(
            "  ok   deploy vault: {} in tx {} gas {}",
            hex(&address),
            receipt.transaction,
            receipt.gas_used
        );
        Ok(address)
    })?;
    let path = out.join("vault-deployment.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "kind": "vault3", "rpc": rpc, "chainId": chain.id, "vault": hex(&vault),
            "token": hex(&token), "verifier": hex(&verifier), "treasury": hex(&treasury),
            "registry": hex(&registry), "maximumTermSeconds": term,
        }))?,
    )?;
    // Read it back the way every agent will, and compare with what was asked.
    let world = World::read(path.to_str().ok_or("path")?)?;
    let expected = vault::Rules::Third {
        maximum_term: term,
        registry,
    };
    if world.deployment.rules != expected
        || world.deployment.treasury != treasury
        || world.deployment.fee_bps != FEE_BPS
        || world.deployment.maximum_fee_bps != MAXIMUM_FEE_BPS
    {
        return Err("the deployed vault does not report the parameters it was given".into());
    }
    let code = chain.code(vault)?;
    println!(
        "  ok   vault {}: {} bytes, code hash {}; treasury {}; registry {}; term {term} s",
        hex(&vault),
        code.len(),
        hex(&keccak(&code)),
        hex(&treasury),
        hex(&registry)
    );
    println!(
        "payer spent {} wei",
        before.saturating_sub(chain.balance(address_of(&payer))?)
    );
    Ok(())
}

/// Pay a payee everything a third-form vault has booked for it in the
/// deployment's token. Any wallet may do this; the caller only pays gas.
///
///   claim DEPLOYMENT KEYFILE PAYEE_ADDRESS
pub fn claim(args: &[String]) -> Res<()> {
    let [deployment, keyfile, payee] = args else {
        return Err("usage: claim DEPLOYMENT KEYFILE PAYEE_ADDRESS".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let world = World::read(deployment)?;
    if world.deployment.rules.form() != vault::Form::Third {
        return Err("this deployment is a second-form vault: use sweep".into());
    }
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let payee = address_arg(payee)?;
    let owed = world.owed(payee)?;
    let before = world.balance(payee)?;
    println!(
        "vault {} owes {} {owed} in token {}; it holds {before}",
        hex(&world.deployment.vault),
        hex(&payee),
        hex(&world.token)
    );
    if owed.is_zero() {
        return Err("nothing owed".into());
    }
    let receipt = world.chain.send(
        &payer,
        Some(world.deployment.vault),
        0,
        &third::claimCall {
            payee: A::from(payee),
            asset: A::from(world.token),
        }
        .abi_encode(),
    )?;
    let after = world.balance(payee)?;
    println!(
        "  {} claim: tx {} gas {}; payee {before} -> {after}",
        if receipt.success { "ok  " } else { "FAIL" },
        receipt.transaction,
        receipt.gas_used
    );
    if receipt.success && after - before == owed && world.owed(payee)?.is_zero() {
        Ok(())
    } else {
        Err("the claim did not deliver the booked amount".into())
    }
}

/// Deploy a base registry (BaseRegistry) for an existing proof verifier and
/// the base program's image ID, with a ceiling on royalty rates in basis
/// points. It has no owner; these three values are fixed forever.
///
///   registry-deploy RPC KEYFILE REGISTRY_BIN VERIFIER_ADDRESS BASE_PROGRAM_HEX MAXIMUM_BPS OUT_JSON
pub fn registry_deploy(args: &[String]) -> Res<()> {
    let [rpc, keyfile, registry_bin, verifier, program, maximum, out] = args else {
        return Err("usage: registry-deploy RPC KEYFILE REGISTRY_BIN VERIFIER_ADDRESS BASE_PROGRAM_HEX MAXIMUM_BPS OUT_JSON".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let verifier = address_arg(verifier)?;
    if chain.code(verifier)?.is_empty() {
        return Err("there is no contract at the verifier address".into());
    }
    let program: [u8; 32] = unhex(program.trim())?
        .try_into()
        .map_err(|_| "program id length")?;
    let maximum: u16 = maximum.parse()?;
    let constructor = (
        A::from(verifier),
        alloy_primitives::B256::from(program),
        maximum,
    )
        .abi_encode();
    let code = [
        unhex(fs::read_to_string(registry_bin)?.trim())?,
        constructor,
    ]
    .concat();
    let receipt = chain.send(&payer, None, 0, &code)?;
    let address = receipt
        .contract
        .filter(|_| receipt.success)
        .ok_or("registry deployment failed")?;
    let runtime = chain.code(address)?;
    println!(
        "  ok   chain {} registry {} for verifier {} and base program {} (ceiling {maximum} bps) in tx {} gas {}; {} bytes, code hash {}",
        chain.id,
        hex(&address),
        hex(&verifier),
        hex(&program),
        receipt.transaction,
        receipt.gas_used,
        runtime.len(),
        hex(&keccak(&runtime))
    );
    fs::write(
        out,
        serde_json::to_vec_pretty(&json!({
            "rpc": rpc, "chainId": chain.id, "registry": hex(&address), "verifier": hex(&verifier),
            "baseProgram": hex(&program), "maximumBps": maximum,
            "deployTransaction": receipt.transaction,
        }))?,
    )?;
    Ok(())
}

/// Register a base on the base program's proof. Any wallet may submit it; the
/// payee and rate are the ones the proof commits.
///
///   registry-register RPC KEYFILE REGISTRY_ADDRESS BASE_ID_HEX AXIOMS_HASH_HEX PAYEE_ADDRESS BPS SEAL_HEX_FILE
pub fn registry_register(args: &[String]) -> Res<()> {
    let [rpc, keyfile, registry, base, axioms, payee, bps, seal] = args else {
        return Err("usage: registry-register RPC KEYFILE REGISTRY_ADDRESS BASE_ID_HEX AXIOMS_HASH_HEX PAYEE_ADDRESS BPS SEAL_HEX_FILE".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    sol! {
        function register(bytes32 base, bytes32 axiomsHash, address payee, uint16 bps, bytes seal);
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let registry = address_arg(registry)?;
    let word = |text: &str| -> Res<[u8; 32]> {
        unhex(text.trim())?
            .try_into()
            .map_err(|_| "32 bytes expected".into())
    };
    let (base, payee) = (word(base)?, address_arg(payee)?);
    let call = registerCall {
        base: base.into(),
        axiomsHash: word(axioms)?.into(),
        payee: A::from(payee),
        bps: bps.parse()?,
        seal: unhex(fs::read_to_string(seal)?.trim())?.into(),
    }
    .abi_encode();
    let receipt = chain.send(&payer, Some(registry), 0, &call)?;
    let entry = crate::world::registry_entry(&chain, registry, base)?;
    println!(
        "  {} register base {}: tx {} gas {}; registry now reports {:?}",
        if receipt.success { "ok  " } else { "FAIL" },
        hex(&base),
        receipt.transaction,
        receipt.gas_used,
        entry.map(|e| (hex(&e.payee), e.bps))
    );
    if receipt.success && entry.is_some_and(|e| e.payee == payee) {
        Ok(())
    } else {
        Err("registration failed".into())
    }
}

/// Ask a chain whether it takes a transaction with this much calldata, by
/// sending one: BYTES of 0x01 from the key's wallet to itself, no value. An
/// artifact travels in `settle`'s calldata, so the answer bounds how large an
/// artifact a seller can be paid for on that chain.
///
///   probe-calldata RPC KEYFILE BYTES
pub fn probe_calldata(args: &[String]) -> Res<()> {
    let [rpc, keyfile, bytes] = args else {
        return Err("usage: probe-calldata RPC KEYFILE BYTES".into());
    };
    if !Path::new(keyfile).exists() {
        return Err("key file does not exist".into());
    }
    let chain = Chain::connect(rpc)?;
    let payer = Keys::load_or_create(keyfile)?.wallet.clone();
    let own = address_of(&payer);
    let bytes: usize = bytes.parse()?;
    let before = chain.balance(own)?;
    match chain.send(&payer, Some(own), 0, &vec![1u8; bytes]) {
        Ok(receipt) => {
            println!(
                "  {} chain {} took {bytes} bytes of calldata: tx {}, gas {}, cost {} wei",
                if receipt.success { "ok  " } else { "FAIL" },
                chain.id,
                receipt.transaction,
                receipt.gas_used,
                before.saturating_sub(chain.balance(own)?)
            );
            Ok(())
        }
        Err(error) => {
            println!(
                "  refused: chain {} would not take {bytes} bytes of calldata: {error}",
                chain.id
            );
            Err("refused".into())
        }
    }
}

#[cfg(test)]
mod send_token_tests {
    use super::*;

    /// The call is the standard ERC-20 transfer: selector a9059cbb, then the
    /// recipient and the amount as two words.
    #[test]
    fn the_token_transfer_call_is_the_standard_one() {
        let call = token_transfer_call([0x11; 20], U256::from(1_000_000u64));
        assert_eq!(call.len(), 68);
        assert_eq!(call[..4], [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(call[4..16], [0; 12]);
        assert_eq!(call[16..36], [0x11; 20]);
        assert_eq!(U256::from_be_slice(&call[36..]), U256::from(1_000_000u64));
    }
}
