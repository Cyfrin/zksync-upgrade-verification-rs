use ethers::{
    abi::{encode, decode, ParamType, Token},
    providers::{Http, Provider},
    types::{Address, Bytes, H256, U256},
    middleware::Middleware,
    utils::keccak256
};
use colored::Colorize;
use eyre::{eyre, Result};
use clap::{Parser, Subcommand};
use std::env;
use std::str::FromStr;
use reqwest;

const VERSION: &str = "0.0.6";
const PROPOSAL_CREATED_TOPIC: &str = "0x7d84a6263ae0d98d3329bd7b46bb4e8d6f98cd35a7adb45c274c8b7fd5ebd5e0";
const DEFAULT_GOVERNOR: &str = "0x76705327e682F2d96943280D99464Ab61219e34f";

#[derive(Parser)]
#[command(author, version = VERSION, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true)]
    rpc_url: Option<String>,

    #[arg(long, global = true, default_value = DEFAULT_GOVERNOR)]
    governor: String,

    #[arg(long, global = true)]
    decode: bool,
}

#[derive(Subcommand)]
enum Commands {
    GetZkId { tx_hash: String },
    GetUpgrades { tx_hash: String },
    GetEthId { tx_hash: String },
}

async fn get_provider(rpc_url: &str) -> Result<Provider<Http>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    Ok(provider)
}

async fn get_zk_id(tx_hash: &str, rpc_url: &str, _governor: &str) -> Result<()> {
    let provider = get_provider(rpc_url).await?;
    let tx_hash = H256::from_str(tx_hash).map_err(|_| eyre!("Invalid transaction hash format"))?;
    let receipt = provider
        .get_transaction_receipt(tx_hash)
        .await?
        .ok_or_else(|| eyre!("Transaction receipt not found"))?;
    let proposal_topic = H256::from_str(PROPOSAL_CREATED_TOPIC)
        .map_err(|_| eyre!("Invalid topic format"))?;
    let proposal_log = receipt
        .logs
        .iter()
        .find(|log| !log.topics.is_empty() && log.topics[0] == proposal_topic)
        .ok_or_else(|| eyre!("Proposal created event not found in transaction logs"))?;
    let proposal_id_hex = &proposal_log.data.0[..32];
    let proposal_id = U256::from_big_endian(proposal_id_hex);
    print_header("Proposal ID");
    print_field("Hex", &format!("0x{}", hex::encode(proposal_id_hex)));
    print_field("Decimal", &proposal_id.to_string());
    Ok(())
}

async fn decode_calldata(calldata: &[u8]) -> Result<String> {
    if calldata.len() < 4 {
        return Ok("Invalid calldata".to_string());
    }

    let client = reqwest::Client::new();

    let selector = &calldata[..4];
    let selector_hex = format!("0x{}", hex::encode(selector));
    
    let response = client
        .get(format!("https://api.openchain.xyz/signature-database/v1/lookup?function={}&filter=true", selector_hex))
        .header("accept", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(function) = result.get("result")
            .and_then(|r| r.get("function"))
            .and_then(|f| f.get(&selector_hex))
            .and_then(|arr| arr.as_array())
            .and_then(|arr| arr.first()) {
                
            let name = function.get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown function");
            // If we have parameters in the calldata, try to decode them
            if calldata.len() > 4 {
                    // Parse the text signature to get parameter types
                    if let Some(param_types) = parse_signature(name) {
                        match decode(&param_types, &calldata[4..]) {
                            Ok(decoded) => {
                                let params = decoded.iter()
                                    .map(format_token)
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                return Ok(format!("{}({})", name, params));
                            }
                            Err(_) => return Ok(format!("{}()", name))
 
                        }
                    }
            }
            return Ok(format!("{}()", name));
        }
    }
    
    Ok("Unknown function".to_string())
}

fn format_token(token: &Token) -> String {
    match token {
        Token::Address(addr) => format!("{:#x}", addr),
        Token::Uint(num) => num.to_string(),
        Token::Int(num) => num.to_string(),
        Token::Bool(b) => b.to_string(),
        Token::String(s) => format!("\"{}\"", s),
        Token::Bytes(b) => format!("0x{}", hex::encode(b)),
        Token::FixedBytes(b) => format!("0x{}", hex::encode(b)),
        Token::Array(arr) => format!("[{}]", arr.iter().map(format_token).collect::<Vec<_>>().join(", ")),
        Token::FixedArray(arr) => format!("[{}]", arr.iter().map(format_token).collect::<Vec<_>>().join(", ")),
        Token::Tuple(tuple) => format!("({})", tuple.iter().map(format_token).collect::<Vec<_>>().join(", ")),
    }
}

fn parse_signature(text_signature: &str) -> Option<Vec<ParamType>> {
    // Extract parameters part from the signature (between parentheses)
    let start = text_signature.find('(')?;
    let end = text_signature.rfind(')')?;
    let params_str = &text_signature[start + 1..end];
    
    // If no parameters, return empty vec
    if params_str.is_empty() {
        return Some(vec![]);
    }
    
    // Split parameters and convert to ParamType, handling nested tuples
    let mut params = Vec::new();
    let mut current_param = String::new();
    let mut paren_count = 0;
    
    for c in params_str.chars() {
        match c {
            '(' => {
                paren_count += 1;
                current_param.push(c);
            }
            ')' => {
                paren_count -= 1;
                current_param.push(c);
            }
            ',' if paren_count == 0 => {
                if !current_param.is_empty() {
                    if let Ok(param_type) = parse_param_type(&current_param.trim()) {
                        params.push(param_type);
                    }
                    current_param.clear();
                }
            }
            _ => current_param.push(c)
        }
    }
    
    // Don't forget the last parameter
    if !current_param.is_empty() {
        if let Ok(param_type) = parse_param_type(&current_param.trim()) {
            params.push(param_type);
        }
    }
    
    Some(params)
}

fn parse_param_type(param: &str) -> Result<ParamType, eyre::Error> {
    // Handle arrays first
    if param.ends_with("[]") {
        let inner_type = &param[..param.len() - 2];
        return Ok(ParamType::Array(Box::new(parse_param_type(inner_type)?)));
    }
    
    // Handle tuples
    if param.starts_with('(') && param.ends_with(')') {
        let inner_params = &param[1..param.len() - 1];
        let mut tuple_params = Vec::new();
        let mut current_param = String::new();
        let mut paren_count = 0;
        
        for c in inner_params.chars() {
            match c {
                '(' => {
                    paren_count += 1;
                    current_param.push(c);
                }
                ')' => {
                    paren_count -= 1;
                    current_param.push(c);
                }
                ',' if paren_count == 0 => {
                    if !current_param.is_empty() {
                        if let Ok(param_type) = parse_param_type(&current_param.trim()) {
                            tuple_params.push(param_type);
                        }
                        current_param.clear();
                    }
                }
                _ => current_param.push(c)
            }
        }
        
        // Handle the last parameter in the tuple
        if !current_param.is_empty() {
            if let Ok(param_type) = parse_param_type(&current_param.trim()) {
                tuple_params.push(param_type);
            }
        }
        
        return Ok(ParamType::Tuple(tuple_params));
    }
    
    // Handle basic types
    match param {
        "address" => Ok(ParamType::Address),
        "uint256" => Ok(ParamType::Uint(256)),
        "uint8" => Ok(ParamType::Uint(8)),
        "bool" => Ok(ParamType::Bool),
        "string" => Ok(ParamType::String),
        "bytes" => Ok(ParamType::Bytes),
        "bytes4" => Ok(ParamType::FixedBytes(4)),
        s if s.starts_with("bytes") => {
            let size: usize = s[5..].parse()?;
            Ok(ParamType::FixedBytes(size))
        }
        s if s.starts_with("uint") => {
            let size: usize = s[4..].parse()?;
            Ok(ParamType::Uint(size))
        }
        s if s.starts_with("int") => {
            let size: usize = s[3..].parse()?;
            Ok(ParamType::Int(size))
        }
        _ => Err(eyre!("Unsupported parameter type: {}", param))
    }
}

pub async fn get_upgrades(tx_hash: &str, rpc_url: &str, should_decode: bool) -> eyre::Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let tx_hash: H256 = tx_hash.parse()?;
    let eth_bridge_address: Address = "0x0000000000000000000000000000000000008008".parse()?;
    let tx = provider
        .get_transaction(tx_hash)
        .await?
        .ok_or_else(|| eyre!("Transaction not found"))?;
    let input_data = tx.input;

    // Define propose function parameters
    let param_types = vec![
        ParamType::Array(Box::new(ParamType::Address)),
        ParamType::Array(Box::new(ParamType::Uint(256))),
        ParamType::Array(Box::new(ParamType::Bytes)),
        ParamType::String,
    ];

    // Decode propose call (skip selector)
    let decoded = decode(&param_types, &input_data[4..])?;
    let targets: Vec<Address> = decoded[0]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| t.into_address().unwrap())
        .collect();
    let values: Vec<U256> = decoded[1]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| t.into_uint().unwrap())
        .collect();
    let calldatas: Vec<Bytes> = decoded[2]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| Bytes::from(t.into_bytes().unwrap()))
        .collect();

    print_header("ZKsync Transactions");

    for (i, ((target, value), calldata)) in targets
        .iter()
        .zip(values.iter())
        .zip(calldatas.iter())
        .enumerate()
    {
        println!("\n{}", format!("ZKsync Transaction #{}:", i + 1).bold());
        print_field("Target Address", &format!("{:?}", target));
        print_field("Value", &value.to_string());
        print_field("Calldata", &format!("0x{}", hex::encode(calldata.as_ref())));

        if *target == eth_bridge_address
            && calldata.len() >= 4
            && &calldata[0..4] == hex::decode("62f84b24")?.as_slice()
        {
            println!("{}", "(ETH transaction)".bold().green());

            // Decode sendToL1(bytes)
            let send_to_l1_data = decode(&[ParamType::Bytes], &calldata[4..])?;
            let l1_data = send_to_l1_data[0].clone().into_bytes().unwrap();

            // Define the parameter type for l1_data
            let l1_param_types = vec![ParamType::Tuple(vec![
                ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::Address,      // Target address
                    ParamType::Uint(256),    // Value
                    ParamType::Bytes,        // Calldata
                ]))),
                ParamType::Address,          // Executor address
                ParamType::FixedBytes(32),   // Salt
            ])];

            // Decode l1_data (starts with offset 0x20)
            let decoded_l1 = decode(&l1_param_types, &l1_data).expect("Failed to decode l1_data");
            let tuple_token = decoded_l1[0].clone();
            let tuple = tuple_token.into_tuple().expect("Expected a tuple");
            let operations = tuple[0].clone().into_array().expect("Expected an array");
            let executor = tuple[1].clone().into_address().expect("Expected an address");
            let salt = tuple[2].clone().into_fixed_bytes().expect("Expected fixed bytes");

            // Display the Ethereum transaction details
            print_header("Ethereum Transaction");
            for (_i, op) in operations.iter().enumerate() {
                let op_tuple = op.clone().into_tuple().expect("Expected a tuple");
                let target = op_tuple[0].clone().into_address().expect("Expected an address");
                let value = op_tuple[1].clone().into_uint().expect("Expected a uint");
                let data = op_tuple[2].clone().into_bytes().expect("Expected bytes");
                println!("  {}", "Call:".bold());
                print_field("    Target", &format!("{:?}", target));
                print_field("    Value", &value.to_string());
                print_field("    Calldata", &format!("0x{}", hex::encode(&data)));
                
                if should_decode {
                    let function_name = decode_calldata(&data).await?;
                    println!("    {}: {} \n", "Function".bold(), function_name.green());
                }
            }
            print_field("\nExecutor", &format!("{:?}", executor));
            print_field("Salt", &format!("0x{}", hex::encode(&salt)));
        }
    }
    Ok(())
}

pub async fn get_eth_id(tx_hash: &str, rpc_url: &str, _governor: &str) -> Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let tx_hash: H256 = tx_hash.parse()?;
    let eth_bridge_address: Address = "0x0000000000000000000000000000000000008008".parse()?;

    let tx = provider
        .get_transaction(tx_hash)
        .await?
        .ok_or_else(|| eyre!("Transaction not found"))?;
    let input_data = tx.input;

    let param_types = vec![
        ParamType::Array(Box::new(ParamType::Address)),
        ParamType::Array(Box::new(ParamType::Uint(256))),
        ParamType::Array(Box::new(ParamType::Bytes)),
        ParamType::String,
    ];

    let decoded = decode(&param_types, &input_data[4..])?;
    let targets: Vec<Address> = decoded[0]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| t.into_address().unwrap())
        .collect();
    let values: Vec<U256> = decoded[1]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| t.into_uint().unwrap())
        .collect();
    let calldatas: Vec<Bytes> = decoded[2]
        .clone()
        .into_array()
        .unwrap()
        .into_iter()
        .map(|t| Bytes::from(t.into_bytes().unwrap())) // Fix: Convert Vec<u8> to Bytes
        .collect();

    let mut eth_tx_counter = 0;

    for ((target, _value), calldata) in targets.iter().zip(values.iter()).zip(calldatas.iter()) {
        if *target == eth_bridge_address
            && calldata.len() >= 4
            && &calldata[0..4] == hex::decode("62f84b24").unwrap().as_slice()
        {
            eth_tx_counter += 1;

            let send_to_l1_data = decode(&[ParamType::Bytes], &calldata[4..])?;
            let l1_data = send_to_l1_data[0].clone().into_bytes().unwrap();

            let l1_param_types = vec![ParamType::Tuple(vec![
                ParamType::Array(Box::new(ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Uint(256),
                    ParamType::Bytes,
                ]))),
                ParamType::Address,
                ParamType::FixedBytes(32),
            ])];

            let decoded_l1 = decode(&l1_param_types, &l1_data)?;
            let tuple = decoded_l1[0].clone().into_tuple().ok_or_else(|| eyre!("Expected a tuple"))?;
            let operations = tuple[0].clone().into_array().ok_or_else(|| eyre!("Expected an array"))?;
            let executor = tuple[1].clone().into_address().ok_or_else(|| eyre!("Expected an address"))?;
            let salt = tuple[2].clone().into_fixed_bytes().ok_or_else(|| eyre!("Expected fixed bytes"))?;

            // Construct the UpgradeProposal token
            let call_tokens: Vec<Token> = operations
                .iter()
                .map(|op| {
                    let op_tuple = op.clone().into_tuple().unwrap();
                    Token::Tuple(vec![
                        Token::Address(op_tuple[0].clone().into_address().unwrap()),
                        Token::Uint(op_tuple[1].clone().into_uint().unwrap()),
                        Token::Bytes(op_tuple[2].clone().into_bytes().unwrap()),
                    ])
                })
                .collect();

            let proposal_token = Token::Tuple(vec![
                Token::Array(call_tokens),
                Token::Address(executor),
                Token::FixedBytes(salt),
            ]);

            // Encode and hash the proposal
            let encoded_proposal = encode(&[proposal_token]);
            let hash = keccak256(&encoded_proposal);
            println!("{}: 0x{}", format!("Ethereum proposal ID #{}", eth_tx_counter).bold(), hex::encode(hash).green());
        }
    }

    if eth_tx_counter == 0 {
        return Err(eyre!("{}", "Error: No ETH transactions found in proposal.".red().bold()));
    }

    println!("\n{}", format!("Total ETH transactions (and therefore, contracts): {}", eth_tx_counter).bold());
    println!("{}", "Please copy paste the contract you're looking for the signature for into the test folder, and run the main test with:".bold());
    println!("{}", "  forge test --mt getHash --mc (contract_name) -vv".green());

    Ok(())
}

fn print_header(header: &str) {
    println!("\n{}", header.underline().bold());
}

fn print_field(label: &str, value: &str) {
    println!("{}: {}", label, value.green().bold());
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("DEBUG").unwrap_or_default() == "true" {
        env::set_var("RUST_LOG", "debug");
        env_logger::init();
    }
    let cli = Cli::parse();
    let rpc_url = cli
        .rpc_url
        .clone()
        .or_else(|| env::var("ZKSYNC_RPC_URL").ok())
        .ok_or_else(|| {
            eyre!("{}", "No RPC URL provided. Either use --rpc-url or set ZKSYNC_RPC_URL environment variable".red().bold())
        })?;
    match cli.command {
        Commands::GetZkId { tx_hash } => {
            get_zk_id(&tx_hash, &rpc_url, &cli.governor).await?;
        }
        Commands::GetUpgrades { tx_hash } => {
            get_upgrades(&tx_hash, &rpc_url, cli.decode).await?;
        }
        Commands::GetEthId { tx_hash } => {
            get_eth_id(&tx_hash, &rpc_url, &cli.governor).await?;
        }
    }
    Ok(())
}