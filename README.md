# BlangJsonGenerator
Small utility to aid in the creation of JSON string mods for the new EternalModLoader.

# Usage
Double click the executable or launch from the terminal.

## Compiling
### Linux / macOS
To compile, you'll need a Rust environment set up with rustup. You can set it up by running:
```
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```
and following the given instructions.

Afterwards, clone this repo:
```
git clone https://github.com/PowerBall253/BlangJsonGenerator.git
```

Finally, cd into the directory and compile with cargo:
```
cd BlangJsonGenerator
cargo build --release
```
The compiled binary will be located at the ./target/release folder.

### Windows
To compile, you'll need a Rust environment set up with rustup and the Visual Studio C++ build tools. You can set it up by downloading rustup from [here](https://www.rust-lang.org/tools/install) and follow the given instructions, then downloading Visual Studio 2019 and selecting the C++ tools for download.

Afterwards, clone this repo using the Git Bash:
```
git clone https://github.com/PowerBall253/BlangJsonGenerator.git
```

Finally, cd into the directory and compile with cargo:
```
cd BlangJsonGenerator
cargo build --release
```
The compiled binary will be located at the .\target\release folder.
