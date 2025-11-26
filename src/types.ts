/**
 * VICAL (Verified Issuer Certificate Authority List) Type Definitions
 * Based on ISO/IEC 18013-5:2021 Annex C
 */

// COSE_Sign1 구조
export interface CoseSign1 {
  protectedHeader: Buffer;
  unprotectedHeader: Map<number, unknown>;
  payload: Buffer;
  signature: Buffer;
}

// COSE Header Labels
export const COSE_HEADER = {
  ALG: 1,        // Algorithm
  KID: 4,        // Key ID
  X5CHAIN: 33,   // X.509 Certificate Chain
} as const;

// COSE Algorithm Values
export const COSE_ALG = {
  ES256: -7,     // ECDSA w/ SHA-256
  ES384: -35,    // ECDSA w/ SHA-384
  ES512: -36,    // ECDSA w/ SHA-512
  EdDSA: -8,     // EdDSA
} as const;

// CertificateInfo 구조
export interface CertificateInfo {
  /** DER-encoded X.509 certificate (필수) */
  certificate: Buffer;
  
  /** Certificate serial number (필수) */
  serialNumber: bigint;
  
  /** Subject Key Identifier (필수) */
  ski: Buffer;
  
  /** Document types this certificate can verify (필수) */
  docType: string[];
  
  /** Certificate profile URNs (선택) */
  certificateProfile?: string[];
  
  /** Name of the issuing authority (선택) */
  issuingAuthority?: string;
  
  /** ISO 3166-1 or ISO 3166-2 country code (선택) */
  issuingCountry?: string;
  
  /** State or province name (선택) */
  stateOrProvinceName?: string;
  
  /** DER-encoded Issuer field (선택) */
  issuer?: Buffer;
  
  /** DER-encoded Subject field (선택) */
  subject?: Buffer;
  
  /** Certificate validity start (선택) */
  notBefore?: Date;
  
  /** Certificate validity end (선택) */
  notAfter?: Date;
  
  /** Proprietary extensions (선택) */
  extensions?: Record<string, unknown>;
}

// VICAL 구조
export interface VICAL {
  /** VICAL structure version, currently "1.0" (필수) */
  version: string;
  
  /** Identifies the VICAL provider (필수) */
  vicalProvider: string;
  
  /** Date-time of VICAL issuance (필수) */
  date: Date;
  
  /** Unique, monotonically increasing issue ID (선택) */
  vicalIssueID?: number;
  
  /** Next expected update date-time (선택) */
  nextUpdate?: Date;
  
  /** List of certificate information (필수) */
  certificateInfos: CertificateInfo[];
  
  /** Proprietary extensions (선택) */
  extensions?: Record<string, unknown>;
}

// 서명된 VICAL (COSE_Sign1으로 래핑됨)
export interface SignedVICAL {
  /** COSE_Sign1 structure */
  coseSign1: CoseSign1;
  
  /** Parsed VICAL payload */
  vical: VICAL;
  
  /** Algorithm used for signing */
  algorithm: number;
  
  /** Signer certificate (from x5chain) */
  signerCertificate?: Buffer;
  
  /** Raw bytes for signature verification */
  rawBytes: Buffer;
}

// mDL Document Type
export const MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

// IACA Certificate Profile OID
export const IACA_CERTIFICATE_PROFILE = "1.0.18013.5.1.2";

// VICAL Extended Key Usage OID
export const VICAL_EKU_OID = "1.0.18013.5.1.8";
