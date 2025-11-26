#!/usr/bin/env ts-node
/**
 * VICAL Parser CLI
 * 
 * Usage:
 *   npx ts-node src/cli.ts <vical-file.cbor>
 *   npx ts-node src/cli.ts --json <vical-file.cbor>
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  parseVICAL,
  getAlgorithmName,
  filterMDLCertificates,
  buildTrustAnchors,
  VICALParseError,
  SignedVICAL,
  CertificateInfo,
} from './parser';

interface CLIOptions {
  filePath: string;
  jsonOutput: boolean;
  verbose: boolean;
}

function parseArgs(): CLIOptions {
  const args = process.argv.slice(2);
  
  const options: CLIOptions = {
    filePath: '',
    jsonOutput: false,
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--json' || arg === '-j') {
      options.jsonOutput = true;
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (!arg.startsWith('-')) {
      options.filePath = arg;
    }
  }

  if (!options.filePath) {
    console.error('Error: No input file specified');
    printHelp();
    process.exit(1);
  }

  return options;
}

function printHelp(): void {
  console.log(`
VICAL Parser CLI

Usage:
  npx ts-node src/cli.ts [options] <vical-file.cbor>

Options:
  -j, --json      Output as JSON
  -v, --verbose   Show detailed information
  -h, --help      Show this help

Examples:
  npx ts-node src/cli.ts vical.cbor
  npx ts-node src/cli.ts --json vical.cbor > output.json
  npx ts-node src/cli.ts -v vical.cbor
`);
}

function formatCertInfo(cert: CertificateInfo, verbose: boolean): object {
  const info: Record<string, unknown> = {
    issuingCountry: cert.issuingCountry,
    issuingAuthority: cert.issuingAuthority,
    serialNumber: cert.serialNumber.toString(),
    ski: cert.ski.toString('hex'),
    docType: cert.docType,
  };

  if (cert.stateOrProvinceName) {
    info.stateOrProvinceName = cert.stateOrProvinceName;
  }
  if (cert.certificateProfile) {
    info.certificateProfile = cert.certificateProfile;
  }
  if (cert.notBefore) {
    info.notBefore = cert.notBefore.toISOString();
  }
  if (cert.notAfter) {
    info.notAfter = cert.notAfter.toISOString();
  }

  if (verbose) {
    info.certificateSize = cert.certificate.length;
    info.certificateHex = cert.certificate.toString('hex').substring(0, 100) + '...';
  }

  return info;
}

function formatSignedVICAL(signedVical: SignedVICAL, verbose: boolean): object {
  const output: Record<string, unknown> = {
    version: signedVical.vical.version,
    vicalProvider: signedVical.vical.vicalProvider,
    date: signedVical.vical.date.toISOString(),
    algorithm: getAlgorithmName(signedVical.algorithm),
    certificateCount: signedVical.vical.certificateInfos.length,
  };

  if (signedVical.vical.vicalIssueID !== undefined) {
    output.vicalIssueID = signedVical.vical.vicalIssueID;
  }
  if (signedVical.vical.nextUpdate) {
    output.nextUpdate = signedVical.vical.nextUpdate.toISOString();
  }

  output.certificates = signedVical.vical.certificateInfos.map(
    cert => formatCertInfo(cert, verbose)
  );

  if (verbose) {
    output.rawSize = signedVical.rawBytes.length;
    output.signatureSize = signedVical.coseSign1.signature.length;
    
    if (signedVical.signerCertificate) {
      output.signerCertificateSize = signedVical.signerCertificate.length;
    }

    // mDL specific
    const mdlCerts = filterMDLCertificates(signedVical.vical);
    output.mdlCertificateCount = mdlCerts.length;

    const trustAnchors = buildTrustAnchors(signedVical.vical);
    output.supportedCountries = Array.from(trustAnchors.keys());
  }

  return output;
}

function printHumanReadable(signedVical: SignedVICAL, verbose: boolean): void {
  console.log('═'.repeat(60));
  console.log('VICAL Information');
  console.log('═'.repeat(60));
  
  console.log(`Version:         ${signedVical.vical.version}`);
  console.log(`Provider:        ${signedVical.vical.vicalProvider}`);
  console.log(`Date:            ${signedVical.vical.date.toISOString()}`);
  
  if (signedVical.vical.vicalIssueID !== undefined) {
    console.log(`Issue ID:        ${signedVical.vical.vicalIssueID}`);
  }
  if (signedVical.vical.nextUpdate) {
    console.log(`Next Update:     ${signedVical.vical.nextUpdate.toISOString()}`);
  }
  
  console.log(`Algorithm:       ${getAlgorithmName(signedVical.algorithm)}`);
  console.log(`Certificates:    ${signedVical.vical.certificateInfos.length}`);

  if (verbose) {
    console.log(`Raw Size:        ${signedVical.rawBytes.length} bytes`);
    console.log(`Signature Size:  ${signedVical.coseSign1.signature.length} bytes`);
    
    if (signedVical.signerCertificate) {
      console.log(`Signer Cert:     ${signedVical.signerCertificate.length} bytes`);
    }
  }

  console.log();
  console.log('─'.repeat(60));
  console.log('Certificate List');
  console.log('─'.repeat(60));

  for (let i = 0; i < signedVical.vical.certificateInfos.length; i++) {
    const cert = signedVical.vical.certificateInfos[i];
    
    console.log();
    console.log(`[${i + 1}] ${cert.issuingCountry || 'Unknown'} - ${cert.issuingAuthority || 'Unknown'}`);
    console.log(`    Serial:    ${cert.serialNumber}`);
    console.log(`    SKI:       ${cert.ski.toString('hex')}`);
    console.log(`    Doc Types: ${cert.docType.join(', ')}`);
    
    if (cert.stateOrProvinceName) {
      console.log(`    State:     ${cert.stateOrProvinceName}`);
    }
    if (cert.certificateProfile) {
      console.log(`    Profile:   ${cert.certificateProfile.join(', ')}`);
    }
    if (cert.notBefore && cert.notAfter) {
      console.log(`    Validity:  ${cert.notBefore.toISOString()} ~ ${cert.notAfter.toISOString()}`);
    }
    
    if (verbose) {
      console.log(`    Cert Size: ${cert.certificate.length} bytes`);
    }
  }

  // Trust anchor summary
  console.log();
  console.log('─'.repeat(60));
  console.log('mDL Trust Anchors');
  console.log('─'.repeat(60));
  
  const trustAnchors = buildTrustAnchors(signedVical.vical);
  console.log(`Supported countries: ${trustAnchors.size}`);
  
  const countries = Array.from(trustAnchors.keys()).sort();
  console.log(countries.join(', '));

  console.log();
  console.log('═'.repeat(60));
}

async function main(): Promise<void> {
  const options = parseArgs();

  // 파일 읽기
  if (!fs.existsSync(options.filePath)) {
    console.error(`Error: File not found: ${options.filePath}`);
    process.exit(1);
  }

  const absolutePath = path.resolve(options.filePath);
  const fileBuffer = fs.readFileSync(absolutePath);

  console.error(`Reading: ${absolutePath}`);
  console.error(`File size: ${fileBuffer.length} bytes`);
  console.error();

  try {
    const signedVical = parseVICAL(fileBuffer);

    if (options.jsonOutput) {
      const output = formatSignedVICAL(signedVical, options.verbose);
      console.log(JSON.stringify(output, null, 2));
    } else {
      printHumanReadable(signedVical, options.verbose);
    }

  } catch (error) {
    if (error instanceof VICALParseError) {
      console.error(`Parse Error: ${error.message}`);
      if (options.verbose && error.cause) {
        console.error(`Cause:`, error.cause);
      }
      process.exit(1);
    }
    throw error;
  }
}

main().catch(error => {
  console.error('Unexpected error:', error);
  process.exit(1);
});
