import { encode } from 'cbor-x';
import {
  parseVICAL,
  filterMDLCertificates,
  findByCountry,
  buildTrustAnchors,
  getAlgorithmName,
  VICALParseError,
  MDL_DOCTYPE,
} from './parser';

/**
 * 테스트용 가짜 VICAL 데이터 생성
 */
function createMockVICAL(): Buffer {
  // Mock DER certificate (실제로는 유효한 X.509 인증서)
  const mockCertKR = Buffer.from('308203A7...Korean IACA mock...', 'utf8');
  const mockCertUS = Buffer.from('308203B2...US-CA IACA mock...', 'utf8');
  const mockCertDE = Buffer.from('308203C1...German IACA mock...', 'utf8');

  // VICAL Payload
  const vicalPayload = {
    version: '1.0',
    vicalProvider: 'Example VICAL Provider',
    date: new Date('2024-11-01T00:00:00Z'),
    vicalIssueID: 157,
    nextUpdate: new Date('2025-01-30T00:00:00Z'),
    certificateInfos: [
      {
        certificate: mockCertKR,
        serialNumber: BigInt('1234567890'),
        ski: Buffer.from('A1B2C3D4E5F6', 'hex'),
        docType: [MDL_DOCTYPE],
        certificateProfile: ['1.0.18013.5.1.2'],
        issuingAuthority: '대한민국 경찰청',
        issuingCountry: 'KR',
        notBefore: new Date('2023-01-01T00:00:00Z'),
        notAfter: new Date('2033-01-01T00:00:00Z'),
      },
      {
        certificate: mockCertUS,
        serialNumber: BigInt('9876543210'),
        ski: Buffer.from('F6E5D4C3B2A1', 'hex'),
        docType: [MDL_DOCTYPE],
        certificateProfile: ['1.0.18013.5.1.2'],
        issuingAuthority: 'California DMV',
        issuingCountry: 'US-CA',
        stateOrProvinceName: 'California',
        notBefore: new Date('2022-06-01T00:00:00Z'),
        notAfter: new Date('2032-06-01T00:00:00Z'),
      },
      {
        certificate: mockCertDE,
        serialNumber: BigInt('5555555555'),
        ski: Buffer.from('112233445566', 'hex'),
        docType: [MDL_DOCTYPE],
        issuingAuthority: 'Kraftfahrt-Bundesamt',
        issuingCountry: 'DE',
        notBefore: new Date('2023-03-15T00:00:00Z'),
        notAfter: new Date('2033-03-15T00:00:00Z'),
      },
    ],
  };

  // VICAL payload를 CBOR로 인코딩
  const payloadBytes = encode(vicalPayload);

  // Protected header: { 1: -7 } (alg: ES256)
  const protectedHeader = encode({ 1: -7 });

  // Mock signer certificate
  const mockSignerCert = Buffer.from('308203FF...VICAL Signer mock...', 'utf8');

  // Unprotected header with x5chain
  const unprotectedHeader = new Map<number, unknown>();
  unprotectedHeader.set(33, mockSignerCert); // x5chain

  // Mock signature (실제로는 유효한 ECDSA 서명)
  const mockSignature = Buffer.alloc(64, 0xAB);

  // COSE_Sign1 구조: [protected, unprotected, payload, signature]
  const coseSign1 = [
    protectedHeader,
    unprotectedHeader,
    payloadBytes,
    mockSignature,
  ];

  // Tag 18 (COSE_Sign1)로 인코딩
  // cbor-x에서는 Tag 클래스 사용
  const { Tag } = require('cbor-x');
  const taggedCoseSign1 = new Tag(coseSign1, 18);

  return Buffer.from(encode(taggedCoseSign1));
}

/**
 * 메인 예제
 */
async function main() {
  console.log('='.repeat(60));
  console.log('VICAL Parser Example');
  console.log('='.repeat(60));
  console.log();

  // 1. Mock VICAL 생성
  console.log('1. Creating mock VICAL data...');
  const vicalBytes = createMockVICAL();
  console.log(`   VICAL size: ${vicalBytes.length} bytes`);
  console.log();

  // 2. VICAL 파싱
  console.log('2. Parsing VICAL...');
  try {
    const signedVical = parseVICAL(vicalBytes);
    
    console.log('   ✓ Successfully parsed VICAL');
    console.log();

    // 3. 기본 정보 출력
    console.log('3. VICAL Information:');
    console.log(`   Version: ${signedVical.vical.version}`);
    console.log(`   Provider: ${signedVical.vical.vicalProvider}`);
    console.log(`   Issue Date: ${signedVical.vical.date.toISOString()}`);
    console.log(`   Issue ID: ${signedVical.vical.vicalIssueID}`);
    console.log(`   Next Update: ${signedVical.vical.nextUpdate?.toISOString()}`);
    console.log(`   Algorithm: ${getAlgorithmName(signedVical.algorithm)}`);
    console.log(`   Certificate Count: ${signedVical.vical.certificateInfos.length}`);
    console.log();

    // 4. 인증서 목록
    console.log('4. Certificate List:');
    console.log('-'.repeat(60));
    
    for (const cert of signedVical.vical.certificateInfos) {
      console.log(`   Country: ${cert.issuingCountry}`);
      console.log(`   Authority: ${cert.issuingAuthority}`);
      console.log(`   Serial Number: ${cert.serialNumber}`);
      console.log(`   SKI: ${cert.ski.toString('hex')}`);
      console.log(`   Doc Types: ${cert.docType.join(', ')}`);
      console.log(`   Valid: ${cert.notBefore?.toISOString()} ~ ${cert.notAfter?.toISOString()}`);
      console.log('-'.repeat(60));
    }
    console.log();

    // 5. mDL 인증서만 필터링
    console.log('5. Filtering mDL certificates:');
    const mdlCerts = filterMDLCertificates(signedVical.vical);
    console.log(`   Found ${mdlCerts.length} mDL certificates`);
    console.log();

    // 6. 국가별 검색
    console.log('6. Finding certificate by country:');
    const krCert = findByCountry(signedVical.vical, 'KR');
    if (krCert) {
      console.log(`   Found KR certificate: ${krCert.issuingAuthority}`);
    }
    
    const jpCert = findByCountry(signedVical.vical, 'JP');
    console.log(`   JP certificate: ${jpCert ? 'Found' : 'Not found'}`);
    console.log();

    // 7. Trust Anchor 맵 생성
    console.log('7. Building trust anchor map:');
    const trustAnchors = buildTrustAnchors(signedVical.vical);
    console.log(`   Trust anchors for ${trustAnchors.size} countries:`);
    for (const [country, cert] of trustAnchors) {
      console.log(`   - ${country}: ${cert.issuingAuthority}`);
    }
    console.log();

    // 8. 실제 mDL 검증 시나리오
    console.log('8. Example: mDL Verification Scenario');
    console.log('-'.repeat(60));
    
    const incomingMdlCountry = 'KR'; // mDL에서 추출한 발급국가
    
    const iacaCert = trustAnchors.get(incomingMdlCountry);
    if (iacaCert) {
      console.log(`   ✓ Found IACA for ${incomingMdlCountry}`);
      console.log(`   ✓ Authority: ${iacaCert.issuingAuthority}`);
      console.log(`   ✓ Certificate size: ${iacaCert.certificate.length} bytes`);
      console.log('   → Ready to verify mDL signature with this IACA');
      
      // 실제 검증 코드 (pseudo)
      // const iacaPublicKey = extractPublicKey(iacaCert.certificate);
      // const isValid = verifyMSOSignature(mdl.mso, iacaPublicKey);
    } else {
      console.log(`   ✗ No IACA found for ${incomingMdlCountry}`);
      console.log('   → Cannot verify mDL from this country');
    }

  } catch (error) {
    if (error instanceof VICALParseError) {
      console.error(`Parse Error: ${error.message}`);
      if (error.cause) {
        console.error(`Cause: ${error.cause}`);
      }
    } else {
      throw error;
    }
  }

  console.log();
  console.log('='.repeat(60));
  console.log('Example completed');
  console.log('='.repeat(60));
}

// 실행
main().catch(console.error);
