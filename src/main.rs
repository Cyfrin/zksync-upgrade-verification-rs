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

pub async fn get_upgrades(tx_hash: &str, rpc_url: &str) -> eyre::Result<()> {
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
        println!("\nZKsync Transaction #{}:", i + 1);
        print_field("Target Address", &format!("{:?}", target));
        print_field("Value", &value.to_string());
        print_field("Calldata", &format!("0x{}", hex::encode(calldata.as_ref())));

        if *target == eth_bridge_address
            && calldata.len() >= 4
            && &calldata[0..4] == hex::decode("62f84b24")?.as_slice()
        {
            println!("{}", "(ETH transaction)".bold());

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
                println!("  Call:");
                println!("  Target: {:?}", target);
                println!("  Value: {}", value);
                println!("  Calldata:  0x{}", hex::encode(&data));
            }
            println!("\nExecutor: {:?}", executor);
            println!("Salt: 0x{}", hex::encode(&salt));
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
            println!("Ethereum proposal ID #{}: 0x{}", eth_tx_counter, hex::encode(hash));
        }
    }

    if eth_tx_counter == 0 {
        return Err(eyre!("Error: No ETH transactions found in proposal."));
    }

    Ok(())
}

fn print_header(header: &str) {
    println!("\n{}", header.underline());
}

fn print_field(label: &str, value: &str) {
    println!("{}: {}", label, value.green());
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
            eyre!("No RPC URL provided. Either use --rpc-url or set ZKSYNC_RPC_URL environment variable")
        })?;
    match cli.command {
        Commands::GetZkId { tx_hash } => {
            get_zk_id(&tx_hash, &rpc_url, &cli.governor).await?;
        }
        Commands::GetUpgrades { tx_hash } => {
            get_upgrades(&tx_hash, &rpc_url).await?;
        }
        Commands::GetEthId { tx_hash } => {
            get_eth_id(&tx_hash, &rpc_url, &cli.governor).await?;
        }
    }
    Ok(())
}