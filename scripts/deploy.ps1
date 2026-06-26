Write-Host "Deploying Axon TLS 1.3 Engine" -ForegroundColor Green

$build_dir = "build"
if (Test-Path $build_dir) {
    Remove-Item -Recurse -Force $build_dir
}

New-Item -ItemType Directory -Path $build_dir

cmake -B $build_dir -DCMAKE_BUILD_TYPE=Release
cmake --build $build_dir --config Release

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful" -ForegroundColor Green
    cmake --install $build_dir --prefix /usr/local
} else {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}