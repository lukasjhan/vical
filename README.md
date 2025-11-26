# vical-parser

A TypeScript parser for **VICAL** (Verified Issuer Certificate Authority List) as defined in [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) Annex C.

VICAL is used to distribute trusted IACA (Issuing Authority Certificate Authority) certificates for verifying mobile driving licenses (mDL).

## Features

- Parse CBOR-encoded VICAL files wrapped in COSE_Sign1
- Extract certificate information including issuing authority, country, validity period
- Filter certificates by document type (e.g., mDL)
- Build trust anchor maps by country code
- CLI tool for inspecting VICAL files
- Full TypeScript support with type definitions

## Installation

```bash
npm install vical-parser
```

Or with pnpm:

```bash
pnpm add vical-parser
```

## Usage

### Basic Parsing

```typescript
import { parseVICAL, getAlgorithmName } from "vical-parser";
import * as fs from "fs";

// Read VICAL file
const vicalBytes = fs.readFileSync("vical.cbor");

// Parse VICAL
const signedVical = parseVICAL(vicalBytes);

// Access VICAL metadata
console.log(`Version: ${signedVical.vical.version}`);
console.log(`Provider: ${signedVical.vical.vicalProvider}`);
console.log(`Date: ${signedVical.vical.date.toISOString()}`);
console.log(`Algorithm: ${getAlgorithmName(signedVical.algorithm)}`);
console.log(`Certificates: ${signedVical.vical.certificateInfos.length}`);
```

### Filtering Certificates

```typescript
import {
  parseVICAL,
  filterMDLCertificates,
  filterByDocType,
  findByCountry,
  findBySKI,
} from "vical-parser";

const signedVical = parseVICAL(vicalBytes);

// Get all mDL certificates
const mdlCerts = filterMDLCertificates(signedVical.vical);

// Filter by custom document type
const customCerts = filterByDocType(signedVical.vical, "org.example.doctype");

// Find certificate by country code
const krCert = findByCountry(signedVical.vical, "KR");

// Find certificate by Subject Key Identifier
const cert = findBySKI(signedVical.vical, skiBuffer);
```

### Building Trust Anchors

```typescript
import { parseVICAL, buildTrustAnchors, MDL_DOCTYPE } from "vical-parser";

const signedVical = parseVICAL(vicalBytes);

// Build trust anchor map for mDL verification
const trustAnchors = buildTrustAnchors(signedVical.vical, MDL_DOCTYPE);

// Use in mDL verification
const incomingCountry = "KR";
const iacaCert = trustAnchors.get(incomingCountry);

if (iacaCert) {
  console.log(
    `Found IACA for ${incomingCountry}: ${iacaCert.issuingAuthority}`
  );
  // Use iacaCert.certificate (DER-encoded X.509) for signature verification
}
```

### Error Handling

```typescript
import { parseVICAL, VICALParseError } from "vical-parser";

try {
  const signedVical = parseVICAL(vicalBytes);
} catch (error) {
  if (error instanceof VICALParseError) {
    console.error(`Parse Error: ${error.message}`);
    if (error.cause) {
      console.error(`Cause: ${error.cause}`);
    }
  }
}
```

## CLI

Parse and inspect VICAL files from the command line:

```bash
# Human-readable output
npx ts-node src/cli.ts vical.cbor

# JSON output
npx ts-node src/cli.ts --json vical.cbor

# Verbose output with additional details
npx ts-node src/cli.ts -v vical.cbor

# Export to JSON file
npx ts-node src/cli.ts --json vical.cbor > output.json
```

### CLI Options

| Option          | Description               |
| --------------- | ------------------------- |
| `-j, --json`    | Output as JSON            |
| `-v, --verbose` | Show detailed information |
| `-h, --help`    | Show help                 |

## API Reference

### Functions

#### `parseVICAL(data: Buffer | Uint8Array): SignedVICAL`

Parse a CBOR-encoded VICAL file (COSE_Sign1 wrapped).

#### `getAlgorithmName(alg: number): string`

Get human-readable algorithm name from COSE algorithm value.

#### `filterByDocType(vical: VICAL, docType: string): CertificateInfo[]`

Filter certificates by document type.

#### `filterMDLCertificates(vical: VICAL): CertificateInfo[]`

Filter certificates for mDL document type.

#### `findByCountry(vical: VICAL, countryCode: string): CertificateInfo | undefined`

Find certificate by ISO 3166-1/3166-2 country code.

#### `findBySKI(vical: VICAL, ski: Buffer): CertificateInfo | undefined`

Find certificate by Subject Key Identifier.

#### `buildTrustAnchors(vical: VICAL, docType?: string): Map<string, CertificateInfo>`

Build a map of trust anchors indexed by country code.

### Types

#### `SignedVICAL`

```typescript
interface SignedVICAL {
  coseSign1: CoseSign1; // COSE_Sign1 structure
  vical: VICAL; // Parsed VICAL payload
  algorithm: number; // COSE algorithm value
  signerCertificate?: Buffer; // Signer certificate from x5chain
  rawBytes: Buffer; // Raw bytes for signature verification
}
```

#### `VICAL`

```typescript
interface VICAL {
  version: string; // VICAL version (e.g., "1.0")
  vicalProvider: string; // Provider identifier
  date: Date; // Issuance date
  vicalIssueID?: number; // Monotonically increasing issue ID
  nextUpdate?: Date; // Next expected update
  certificateInfos: CertificateInfo[]; // List of certificates
  extensions?: Record<string, unknown>; // Proprietary extensions
}
```

#### `CertificateInfo`

```typescript
interface CertificateInfo {
  certificate: Buffer; // DER-encoded X.509 certificate
  serialNumber: bigint; // Certificate serial number
  ski: Buffer; // Subject Key Identifier
  docType: string[]; // Supported document types
  certificateProfile?: string[]; // Certificate profile URNs
  issuingAuthority?: string; // Issuing authority name
  issuingCountry?: string; // ISO 3166-1/3166-2 country code
  stateOrProvinceName?: string; // State or province
  issuer?: Buffer; // DER-encoded Issuer field
  subject?: Buffer; // DER-encoded Subject field
  notBefore?: Date; // Validity start
  notAfter?: Date; // Validity end
  extensions?: Record<string, unknown>;
}
```

### Constants

```typescript
// mDL Document Type
MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

// COSE Algorithm Values
COSE_ALG = {
  ES256: -7, // ECDSA w/ SHA-256
  ES384: -35, // ECDSA w/ SHA-384
  ES512: -36, // ECDSA w/ SHA-512
  EdDSA: -8, // EdDSA
};

// COSE Header Labels
COSE_HEADER = {
  ALG: 1, // Algorithm
  KID: 4, // Key ID
  X5CHAIN: 33, // X.509 Certificate Chain
};

// IACA Certificate Profile OID
IACA_CERTIFICATE_PROFILE = "1.0.18013.5.1.2";

// VICAL Extended Key Usage OID
VICAL_EKU_OID = "1.0.18013.5.1.8";
```

## Development

```bash
# Install dependencies
pnpm install

# Build
pnpm build

# Run example
pnpm example

# Run tests
pnpm test
```

## Related Standards

- [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html) - Personal identification — ISO-compliant driving licence — Part 5: Mobile driving licence (mDL) application
- [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152) - CBOR Object Signing and Encryption (COSE)
- [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949) - Concise Binary Object Representation (CBOR)

## License

MIT
