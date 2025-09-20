Write-Host "Installing EDR driver..."
pnputil /add-driver src\edr_kernel\edrdrv.inf /install
