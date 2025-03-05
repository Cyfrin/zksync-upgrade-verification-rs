
# ZKsync Upgrade Verification Tool



## Installation

To install and use the `zkgov-check` tool, follow these steps. Note that the tool is distributed via GitHub Releases, but you may need to build it locally if a compatible binary for your platform (e.g., macOS, Linux, Windows) is not available.

### Prerequisites
- curl
- A ZKsync RPC URL (set as an environment variable, e.g., `export ZKSYNC_RPC_URL=https://zksync-era-rpc.example.com`).

### Option 1: Install from GitHub Release
If a binary for your platform is available in the GitHub Release, you can download and install it directly:

1. Download the latest `zkgov-check` binary for your platform (e.g., macOS, Linux) from the [releases page](https://github.com/Cyfrin/zksync-upgrade-verification-rs/releases):
   ```bash
   curl -L https://github.com/Cyfrin/zksync-upgrade-verification-rs/releases/download/v0.1.0/zkgov-check-linux -o zkgov-check
   ```
   (Replace `zkgov-check-linux` with the appropriate file for your OS, e.g., `zkgov-check-macos`)

2. Make the binary executable:
   ```bash
   chmod +x zkgov-check
   ```

3. Move it to a system directory (e.g., `/usr/local/bin/` on macOS/Linux):
   ```bash
   sudo mv zkgov-check /usr/local/bin/
   ```

4. Verify the installation:
   ```bash
   zkgov-check --help
   ```

**Note**: If the release doesn’t include a binary for your platform (e.g., Windows), proceed to Option 2.

### Option 2: Build from Source
If no pre-built binary is available or you prefer to build locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Cyfrin/zksync-upgrade-verification-rs.git
   cd zksync-upgrade-verification-rs
   ```

2. Build the binary in release mode:
   ```bash
   cargo build --release
   ```

3. Move the binary to a system directory:
   - The binary will be located at `target/release/zkgov-check`.
   - Move it to `/usr/local/bin/` (macOS/Linux) or a directory in your PATH (Windows):
     ```bash
     sudo mv target/release/zkgov-check /usr/local/bin/
     ```
     On Windows, copy `target/release/zkgov-check.exe` to a suitable directory like `C:\Program Files\zkgov-check\` and update your PATH.

4. Verify the installation:
   ```bash
   zkgov-check --help
   ```

## Usage

The `zkgov-check` tool is a command-line application that operates with subcommands, a transaction hash, and an RPC URL to connect to the ZKsync network. The governor address is optional and defaults to `0x76705327e682F2d96943280D99464Ab61219e34f` if omitted. Below are examples of how to use each subcommand:

### 1. Get the ZKsync Proposal ID
Extract the proposal ID from a ZKsync transaction hash:
```bash
zkgov-check get-zk-id <tx-hash> --rpc-url $ZKSYNC_RPC_URL
```
**Output**: The proposal ID in hex and decimal formats, e.g.:
```
Proposal ID
Hex: 0xe06945bf...
Decimal: 101504078...
```

### 2. List Proposal Actions and Ethereum Transactions
Decode a proposal’s actions, including any Ethereum transactions:
```bash
zkgov-check get-upgrades <tx-hash> --rpc-url $ZKSYNC_RPC_URL --decode
```
**Output**: A detailed list of targets, values, and calldata, plus any Ethereum transactions if `sendToL1` is called.

### 3. Compute the Ethereum Proposal ID
Generate the Ethereum-side proposal hash for verification:
```bash
zkgov-check get-eth-id <tx-hash> --rpc-url $ZKSYNC_RPC_URL
```
**Output**: The Keccak-256 hash for each Ethereum transaction in the proposal, e.g.:
```
Ethereum proposal ID #1: 0x5ebd899d...
```

## Practical Examples

Using the ZKsync Upgrade Verification Tool can significantly enhance the security of governance operations. Below is a step-by-step guide for verifying a proposal like [ZIP-7](https://www.tally.xyz/gov/zksync/proposal/53064417471903525695516096129021600825622830249245179379231067906906888383956):

1. **Get the Transaction Hash**: Obtain the transaction hash from a block explorer or Tally for the proposal (e.g., `0x94d49c27617ea2dfd78bb3316e6849bdb1a1dd80ddd22151ecb6c644d3fd86f6`).

2. **Verify the ZKsync Proposal ID**:
   ```bash
   zkgov-check get-zk-id 0x94d49c27617ea2dfd78bb3316e6849bdb1a1dd80ddd22151ecb6c644d3fd86f6 --rpc-url $ZKSYNC_RPC_URL
   ```
   **Output**:
   ```
   Proposal ID
   Hex: 0x7551655cb1bd662c2090a1227ea4eef89a4fdefc83bf33b06ca5b41b53fcadd4
   Decimal: 53064417471903525695516096129021600825622830249245179379231067906906888383956
   ```
   Confirm this matches the ID on Tally.

3. **Fetch the Ethereum Proposal ID**:
   ```bash
   zkgov-check get-eth-id 0x94d49c27617ea2dfd78bb3316e6849bdb1a1dd80ddd22151ecb6c644d3fd86f6 --rpc-url $ZKSYNC_RPC_URL
   ```
   **Output**:
   ```
   Ethereum proposal ID #1: 0x5ebd899d036aae29b12babe196b11380d8304e98ac86390ac18a56ff51ada9bd
   ```

4. **Verify ZKsync and Ethereum Transactions**:
   ```bash
   zkgov-check get-upgrades 0x94d49c27617ea2dfd78bb3316e6849bdb1a1dd80ddd22151ecb6c644d3fd86f6 --decode --rpc-url $ZKSYNC_RPC_URL
   ```
   **Output**: 
   ```bash
       ZKsync Transactions

    ZKsync Transaction #1:
    Target Address: 0x0000000000000000000000000000000000008008
    Value: 0
    Calldata: 0x62f84b24000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000008600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000700000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000360000000000000000000000000000000000000000000000000000000000000044000000000000000000000000000000000000000000000000000000000000005c00000000000000000000000009da9f5dad070649811d77c40ccdcab479ce3fa0700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000479ba509700000000000000000000000000000000000000000000000000000000000000000000000000000000590e6587b37dc4152b6b036ff88a835bd2ab892400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000479ba5097000000000000000000000000000000000000000000000000000000000000000000000000000000005c03468829a26981c410a7930bd4853622f0b2e500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000479ba50970000000000000000000000000000000000000000000000000000000000000000000000000000000034899f8b01cf52160c88ddb9e29ec3c26901916500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000479ba509700000000000000000000000000000000000000000000000000000000000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000440d14edf700000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000c29d04a93f893700015138e3e334eb828dac3cef00000000000000000000000000000000000000000000000000000000000000000000000000000000303a465b659cbb0ab36ee643ea362c509eeb52130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e43f58f5b500000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000001ff1dc3cb9eedbc6eb2d99c03b30a05ca625fb5a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000590e6587b37dc4152b6b036ff88a835bd2ab8924000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000164e34a329a00000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000600000000000000000000000004d89b79a893ac95eb46e96e452ad21f71144c9180000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000640528f3f700000000000000000000000006aa7a7b07108f7c5539645e32dd5c21cbf9eb66000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000005d8ba173dc6c3c90c8f7c04c9288bef5fdbad06e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    (ETH transaction)

    Ethereum Transaction
      Call:
      Target: 0x9da9f5dad070649811d77c40ccdcab479ce3fa07
      Value: 0
      Calldata:  0x79ba5097
      Function: acceptOwnership()() 

      Call:
      Target: 0x590e6587b37dc4152b6b036ff88a835bd2ab8924
      Value: 0
      Calldata:  0x79ba5097
      Function: acceptOwnership()() 

      Call:
      Target: 0x5c03468829a26981c410a7930bd4853622f0b2e5
      Value: 0
      Calldata:  0x79ba5097
      Function: acceptOwnership()() 

      Call:
      Target: 0x34899f8b01cf52160c88ddb9e29ec3c269019165
      Value: 0
      Calldata:  0x79ba5097
      Function: acceptOwnership()() 

      Call:
      Target: 0xc2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c
      Value: 0
      Calldata:  0x0d14edf700000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000c29d04a93f893700015138e3e334eb828dac3cef
      Function: registerAlreadyDeployedHyperchain(uint256,address)(232, 0xc29d04a93f893700015138e3e334eb828dac3cef) 

      Call:
      Target: 0x303a465b659cbb0ab36ee643ea362c509eeb5213
      Value: 0
      Calldata:  0x3f58f5b500000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000001ff1dc3cb9eedbc6eb2d99c03b30a05ca625fb5a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000
      Function: createNewChain(uint256,address,address,uint256,address,bytes)(232, 0xc2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c, 0x1ff1dc3cb9eedbc6eb2d99c03b30a05ca625fb5a, 0, 0x0000000000000000000000000000000000000000, 0x) 

      Call:
      Target: 0x590e6587b37dc4152b6b036ff88a835bd2ab8924
      Value: 0
      Calldata:  0xe34a329a00000000000000000000000000000000000000000000000000000000000000e8000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000600000000000000000000000004d89b79a893ac95eb46e96e452ad21f71144c9180000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000640528f3f700000000000000000000000006aa7a7b07108f7c5539645e32dd5c21cbf9eb66000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000005d8ba173dc6c3c90c8f7c04c9288bef5fdbad06e00000000000000000000000000000000000000000000000000000000
      Function: executeUpgrade(uint256,((address,uint8,bool,bytes4[])[],address,bytes))(232, ([], 0x4d89b79a893ac95eb46e96e452ad21f71144c918, 0x0528f3f700000000000000000000000006aa7a7b07108f7c5539645e32dd5c21cbf9eb66000000000000000000000000c2ee6b6af7d616f6e27ce7f4a451aedc2b0f5f5c0000000000000000000000005d8ba173dc6c3c90c8f7c04c9288bef5fdbad06e)) 


    Executor: 0x0000000000000000000000000000000000000000
    Salt: 0x0000000000000000000000000000000000000000000000000000000000000000
   ```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

