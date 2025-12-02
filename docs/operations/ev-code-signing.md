# EV Code Signing for Windows WFP Driver

This document outlines the process for acquiring and configuring Extended Validation (EV) code signing certificates for the Axiom Hive DDM Windows WFP driver components.

## Overview

Extended Validation (EV) code signing certificates provide the highest level of trust for Windows drivers. They are required for kernel-mode drivers to be loaded on production systems and enable attestation signing through Microsoft's Hardware Dev Center.

## Certificate Authorities

Choose from the following reputable CAs for EV code signing:

### Primary Options

- **DigiCert**: Industry leader with comprehensive Windows driver signing support
- **Sectigo (formerly Comodo)**: Cost-effective option with good Microsoft integration
- **SSL.com**: Budget-friendly with EV code signing capabilities

### Selection Criteria

- Microsoft Hardware Dev Center compatibility
- Token-based certificate delivery
- 24/7 support availability
- Pricing (typically $200-500/year for EV code signing)

## Acquisition Process

### Step 1: Organization Validation

1. Choose your CA and create an account
2. Submit organization details for EV validation:
    - Legal business name
    - Business address
    - Phone number
    - Domain ownership verification
    - Business registration documents
3. Wait for validation (typically 3-7 business days)

### Step 2: Certificate Request

1. Select "EV Code Signing" certificate type
2. Provide certificate details:
    - Organization name (must match validation)
    - Country, State, City
    - Email address
3. Choose token delivery method (USB token recommended)

### Step 3: Installation

1. Receive hardware token via mail
2. Install token drivers on development machine
3. Initialize token with PIN
4. Import certificate to token

## Windows Development Environment Setup

### Prerequisites

- Windows 10/11 Pro or Enterprise
- Visual Studio 2022 with Desktop development workload
- Windows Driver Kit (WDK) 11
- Windows SDK 11

### Installation Steps

```powershell
# Install WDK and SDK
winget install Microsoft.WindowsSDK.11
winget install Microsoft.WindowsWDK.11

# Verify installation
Get-WindowsDriverKitVersion
```

### Driver Project Configuration

Create a new KMDF driver project in Visual Studio:

1. File → New → Project
2. Search for "KMDF" → Kernel Mode Driver (KMDF)
3. Configure project properties:
   - Target Platform: Desktop
   - Minimum OS: Windows 10
   - Driver Model: KMDF 1.33

## Code Signing Configuration

### Development Signing (Test Certificate)

For development and testing:

```powershell
# Create test certificate
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=DDM Test Cert" -CertStoreLocation Cert:\CurrentUser\My

# Export certificate for backup
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
Export-Certificate -Cert $cert -FilePath "C:\DDM\test-cert.cer"

# Sign driver for testing
signtool sign /v /fd sha256 /s MY /n "DDM Test Cert" ddm_wfp.sys
```

### EV Production Signing

For production deployment:

```powershell
# Sign with EV certificate (token-based)
signtool sign /v /fd sha256 /t http://timestamp.digicert.com /csp "eToken Base Cryptographic Provider" /k "[{{Token PIN}}]" ddm_wfp.sys

# Verify signature
signtool verify /v /pa ddm_wfp.sys
```

## Microsoft Hardware Dev Center Submission

### Account Setup

1. Create Microsoft Partner Center account
2. Enroll in Hardware Dev Center program
3. Verify organization identity
4. Set up attestation signing

### Driver Submission Process

1. **Prepare Submission Package**

    ```powershell
    # Create submission directory
    mkdir C:\DDM\submission

    # Copy signed driver
    copy ddm_wfp.sys C:\DDM\submission\

    # Create INF file
    # (Include proper INF configuration for WFP callout driver)
    ```

2. **Create Hardware Submission**
   - Log in to Partner Center
   - Navigate to Hardware → Driver submissions
   - Create new submission
   - Upload signed driver files
   - Provide driver details:
     - Driver name: Axiom Hive DDM WFP Callout
     - Version: 1.0.0
     - Publisher: Your Organization
     - Description: DNS Defense Module kernel filter

3. **Attestation Signing**
   - Submit for Microsoft review
   - Wait for attestation (typically 1-2 weeks)
   - Receive attested signature

### Post-Attestation Signing

After Microsoft attestation:

```powershell
# Apply attested signature
signtool sign /v /fd sha256 /ac "MicrosoftAttested.cer" /t http://timestamp.digicert.com /csp "eToken Base Cryptographic Provider" /k "[{{Token PIN}}]" ddm_wfp.sys
```

## Driver Loading and Testing

### Development Mode Loading

For testing on development machines:

```powershell
# Enable test signing
bcdedit /set testsigning on

# Install driver
pnputil /add-driver ddm_wfp.inf /install

# Load driver
sc create ddm_wfp type= kernel start= demand binPath= "C:\Windows\System32\drivers\ddm_wfp.sys"
sc start ddm_wfp
```

### Production Mode Loading

For production systems (requires EV signature):

```powershell
# Install attested driver
pnputil /add-driver ddm_wfp.inf /install

# Driver will load automatically on system start
```

## Security Considerations

### Token Management

- Store hardware token in secure location
- Use strong PIN (12+ characters, mixed case, numbers, symbols)
- Enable token auto-lock after inactivity
- Maintain backup token for business continuity

### Certificate Lifecycle

- Monitor expiration dates (typically 1-3 years)
- Renew certificates 30 days before expiration
- Update driver signatures with renewed certificates
- Maintain certificate inventory

### Compliance

- Follow Microsoft's driver signing requirements
- Document all signing operations
- Implement change management for driver updates
- Regular security audits of signing infrastructure

## Troubleshooting

### Common Issues

### Token Not Recognized

```powershell
# Check token drivers
certlm.msc
# Look for eToken provider in certificate stores
```

### Signing Fails

- Verify token PIN
- Check certificate validity
- Ensure proper CSP configuration
- Confirm timestamp server accessibility

### Driver Won't Load

- Verify signature with `signtool verify`
- Check Event Viewer for driver loading errors
- Ensure proper INF configuration
- Confirm kernel compatibility

## Cost Estimation

- EV Code Signing Certificate: $200-500/year
- Hardware Token: $50-100 (one-time)
- Microsoft Partner Center: Free (basic), $99/year (advanced)
- Total annual cost: ~$300-700

## Timeline

- Certificate application: 1-2 weeks
- Organization validation: 3-7 business days
- Microsoft attestation: 1-2 weeks
- Total setup time: 4-6 weeks

## Next Steps

1. Begin certificate application process
2. Set up development environment
3. Create and test driver signing workflow
4. Submit to Microsoft for attestation
5. Deploy signed drivers to production

## References

- [Microsoft Hardware Dev Center](https://partner.microsoft.com/en-us/dashboard/hardware)
- [DigiCert EV Code Signing](https://www.digicert.com/code-signing/ev-code-signing)
- [Windows Driver Kit Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [WFP Callout Driver Sample](https://github.com/microsoft/Windows-driver-samples/tree/main/network/wfp)
