#!/bin/bash

# This is an example setup script! You may want to adjust this

sudo apt-get update

# install dependancies
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev curl git zip unzip

sudo apt-get install -y lld-14 llvm-14 llvm-14-dev clang-14 || sudo apt-get install -y lld llvm llvm-dev clang

# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup-init.sh
bash ./rustup-init.sh -y
$HOME/.cargo/bin/rustup toolchain install nightly

# install AFL++
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make source-only
# you will also have to build the qemu target for the qemu-mode demo if you want
sudo make install

cd ..

# install libafl
# instead of using this to build we will just use the packaged version from crates.io
# but I recommend pulling the repo for searching the code and looking at examples
git clone https://github.com/AFLplusplus/LibAFL.git ./libaflsrc/

