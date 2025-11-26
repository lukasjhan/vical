import { decode, decodeMultiple } from 'cbor-x';
import {
  VICAL,
  SignedVICAL,
  CertificateInfo,
  CoseSign1,
  COSE_HEADER,
  COSE_ALG,
  MDL_DOCTYPE,
} from './types';

/**
 * COSE_Sign1 Tag (RFC 8152)
 */
const COSE_SIGN1_TAG = 18;

/**
 * VICAL Parser Error
 */
export class VICALParseError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message);
    this.name = 'VICALParseError';
  }
}

/**
 * Parse tagged date (tdate) from CBOR
 * tdate는 tag 0 (RFC 3339 문자열) 또는 tag 1 (epoch seconds)
 */
function parseDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string') {
    return new Date(value);
  }
  if (typeof value === 'number') {
    return new Date(value * 1000);
  }
  throw new VICALParseError(`Invalid date format: ${typeof value}`);
}

/**
 * Parse bigint from CBOR (biguint)
 */
function parseBigInt(value: unknown): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'number') {
    return BigInt(value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    // CBOR biguint는 tag 2로 인코딩된 바이트열
    const bytes = Buffer.from(value);
    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) + BigInt(byte);
    }
    return result;
  }
  throw new VICALParseError(`Invalid bigint format: ${typeof value}`);
}

/**
 * Parse Buffer from CBOR (bstr)
 */
function parseBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  throw new VICALParseError(`Invalid buffer format: ${typeof value}`);
}

/**
 * Parse string array from CBOR
 */
function parseStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new VICALParseError(`Expected array, got ${typeof value}`);
  }
  return value.map((item, index) => {
    if (typeof item !== 'string') {
      throw new VICALParseError(`Expected string at index ${index}, got ${typeof item}`);
    }
    return item;
  });
}

/**
 * Parse CertificateInfo from CBOR map
 */
function parseCertificateInfo(data: Record<string, unknown>): CertificateInfo {
  // 필수 필드 검증
  if (!data.certificate) {
    throw new VICALParseError('CertificateInfo missing required field: certificate');
  }
  if (data.serialNumber === undefined) {
    throw new VICALParseError('CertificateInfo missing required field: serialNumber');
  }
  if (!data.ski) {
    throw new VICALParseError('CertificateInfo missing required field: ski');
  }
  if (!data.docType) {
    throw new VICALParseError('CertificateInfo missing required field: docType');
  }

  const certInfo: CertificateInfo = {
    certificate: parseBuffer(data.certificate),
    serialNumber: parseBigInt(data.serialNumber),
    ski: parseBuffer(data.ski),
    docType: parseStringArray(data.docType),
  };

  // 선택 필드
  if (data.certificateProfile) {
    certInfo.certificateProfile = parseStringArray(data.certificateProfile);
  }
  if (data.issuingAuthority !== undefined) {
    certInfo.issuingAuthority = String(data.issuingAuthority);
  }
  if (data.issuingCountry !== undefined) {
    certInfo.issuingCountry = String(data.issuingCountry);
  }
  if (data.stateOrProvinceName !== undefined) {
    certInfo.stateOrProvinceName = String(data.stateOrProvinceName);
  }
  if (data.issuer) {
    certInfo.issuer = parseBuffer(data.issuer);
  }
  if (data.subject) {
    certInfo.subject = parseBuffer(data.subject);
  }
  if (data.notBefore !== undefined) {
    certInfo.notBefore = parseDate(data.notBefore);
  }
  if (data.notAfter !== undefined) {
    certInfo.notAfter = parseDate(data.notAfter);
  }
  if (data.extensions) {
    certInfo.extensions = data.extensions as Record<string, unknown>;
  }

  return certInfo;
}

/**
 * Parse VICAL payload from CBOR
 */
function parseVICALPayload(data: Record<string, unknown>): VICAL {
  // 필수 필드 검증
  if (!data.version) {
    throw new VICALParseError('VICAL missing required field: version');
  }
  if (!data.vicalProvider) {
    throw new VICALParseError('VICAL missing required field: vicalProvider');
  }
  if (!data.date) {
    throw new VICALParseError('VICAL missing required field: date');
  }
  if (!data.certificateInfos) {
    throw new VICALParseError('VICAL missing required field: certificateInfos');
  }

  const vical: VICAL = {
    version: String(data.version),
    vicalProvider: String(data.vicalProvider),
    date: parseDate(data.date),
    certificateInfos: [],
  };

  // 선택 필드
  if (data.vicalIssueID !== undefined) {
    vical.vicalIssueID = Number(data.vicalIssueID);
  }
  if (data.nextUpdate !== undefined) {
    vical.nextUpdate = parseDate(data.nextUpdate);
  }
  if (data.extensions) {
    vical.extensions = data.extensions as Record<string, unknown>;
  }

  // certificateInfos 파싱
  if (!Array.isArray(data.certificateInfos)) {
    throw new VICALParseError('certificateInfos must be an array');
  }

  for (const certInfoData of data.certificateInfos) {
    vical.certificateInfos.push(parseCertificateInfo(certInfoData as Record<string, unknown>));
  }

  return vical;
}

/**
 * Parse COSE_Sign1 structure from CBOR
 */
function parseCoseSign1(data: unknown[]): CoseSign1 {
  if (!Array.isArray(data) || data.length !== 4) {
    throw new VICALParseError('Invalid COSE_Sign1 structure: expected array of 4 elements');
  }

  const [protectedHeader, unprotectedHeader, payload, signature] = data;

  return {
    protectedHeader: parseBuffer(protectedHeader),
    unprotectedHeader: unprotectedHeader instanceof Map 
      ? unprotectedHeader 
      : new Map(Object.entries(unprotectedHeader || {})),
    payload: parseBuffer(payload),
    signature: parseBuffer(signature),
  };
}

/**
 * Extract algorithm from COSE protected header
 */
function extractAlgorithm(protectedHeader: Buffer): number {
  const decoded = decode(protectedHeader);
  
  let alg: number | undefined;
  
  if (decoded instanceof Map) {
    alg = decoded.get(COSE_HEADER.ALG);
  } else if (typeof decoded === 'object' && decoded !== null) {
    alg = (decoded as Record<number, unknown>)[COSE_HEADER.ALG] as number;
  }

  if (alg === undefined) {
    throw new VICALParseError('Algorithm not found in protected header');
  }

  return alg;
}

/**
 * Extract signer certificate from x5chain
 */
function extractSignerCertificate(unprotectedHeader: Map<number, unknown>): Buffer | undefined {
  const x5chain = unprotectedHeader.get(COSE_HEADER.X5CHAIN);
  
  if (!x5chain) {
    return undefined;
  }

  // x5chain은 단일 인증서 또는 인증서 배열
  if (Buffer.isBuffer(x5chain) || x5chain instanceof Uint8Array) {
    return Buffer.from(x5chain);
  }

  if (Array.isArray(x5chain) && x5chain.length > 0) {
    // 첫 번째가 end-entity (서명자) 인증서
    const first = x5chain[0];
    if (Buffer.isBuffer(first) || first instanceof Uint8Array) {
      return Buffer.from(first);
    }
  }

  return undefined;
}

/**
 * Main VICAL Parser
 * 
 * @param data - CBOR encoded VICAL (COSE_Sign1 wrapped)
 * @returns Parsed SignedVICAL object
 */
export function parseVICAL(data: Buffer | Uint8Array): SignedVICAL {
  const rawBytes = Buffer.from(data);
  
  let decoded: unknown;
  try {
    decoded = decode(rawBytes);
  } catch (error) {
    throw new VICALParseError('Failed to decode CBOR', error);
  }

  // COSE_Sign1은 tag 18
  // cbor-x는 tagged value를 { tag, value } 형태 또는 직접 배열로 반환할 수 있음
  let coseArray: unknown[];

  if (Array.isArray(decoded)) {
    coseArray = decoded;
  } else if (typeof decoded === 'object' && decoded !== null) {
    const tagged = decoded as { tag?: number; value?: unknown };
    if (tagged.tag === COSE_SIGN1_TAG && Array.isArray(tagged.value)) {
      coseArray = tagged.value;
    } else {
      throw new VICALParseError('Invalid COSE_Sign1: missing tag 18');
    }
  } else {
    throw new VICALParseError(`Invalid COSE_Sign1 format: ${typeof decoded}`);
  }

  // COSE_Sign1 파싱
  const coseSign1 = parseCoseSign1(coseArray);

  // Algorithm 추출
  const algorithm = extractAlgorithm(coseSign1.protectedHeader);

  // Signer certificate 추출
  const signerCertificate = extractSignerCertificate(coseSign1.unprotectedHeader);

  // VICAL payload 디코딩
  let vicalData: unknown;
  try {
    vicalData = decode(coseSign1.payload);
  } catch (error) {
    throw new VICALParseError('Failed to decode VICAL payload', error);
  }

  if (typeof vicalData !== 'object' || vicalData === null) {
    throw new VICALParseError('Invalid VICAL payload: expected object');
  }

  // VICAL 파싱
  const vical = parseVICALPayload(vicalData as Record<string, unknown>);

  return {
    coseSign1,
    vical,
    algorithm,
    signerCertificate,
    rawBytes,
  };
}

/**
 * Get algorithm name from COSE algorithm value
 */
export function getAlgorithmName(alg: number): string {
  switch (alg) {
    case COSE_ALG.ES256:
      return 'ES256 (ECDSA w/ SHA-256)';
    case COSE_ALG.ES384:
      return 'ES384 (ECDSA w/ SHA-384)';
    case COSE_ALG.ES512:
      return 'ES512 (ECDSA w/ SHA-512)';
    case COSE_ALG.EdDSA:
      return 'EdDSA';
    default:
      return `Unknown (${alg})`;
  }
}

/**
 * Filter certificates by document type
 */
export function filterByDocType(vical: VICAL, docType: string): CertificateInfo[] {
  return vical.certificateInfos.filter(cert => cert.docType.includes(docType));
}

/**
 * Filter certificates for mDL
 */
export function filterMDLCertificates(vical: VICAL): CertificateInfo[] {
  return filterByDocType(vical, MDL_DOCTYPE);
}

/**
 * Find certificate by country code
 */
export function findByCountry(vical: VICAL, countryCode: string): CertificateInfo | undefined {
  return vical.certificateInfos.find(cert => cert.issuingCountry === countryCode);
}

/**
 * Find certificate by Subject Key Identifier
 */
export function findBySKI(vical: VICAL, ski: Buffer): CertificateInfo | undefined {
  return vical.certificateInfos.find(cert => cert.ski.equals(ski));
}

/**
 * Build trust anchor map by country
 */
export function buildTrustAnchors(vical: VICAL, docType: string = MDL_DOCTYPE): Map<string, CertificateInfo> {
  const anchors = new Map<string, CertificateInfo>();
  
  for (const cert of vical.certificateInfos) {
    if (cert.docType.includes(docType) && cert.issuingCountry) {
      anchors.set(cert.issuingCountry, cert);
    }
  }
  
  return anchors;
}

export { VICAL, SignedVICAL, CertificateInfo, COSE_HEADER, COSE_ALG, MDL_DOCTYPE };
