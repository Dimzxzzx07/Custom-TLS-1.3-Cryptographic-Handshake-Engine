#!/bin/bash

echo "Building Axon TLS 1.3 Engine"

mkdir -p build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

if [ $? -eq 0 ]; then
    echo "Build successful"
    sudo make install
else
    echo "Build failed"
    exit 1
fi