import { parseVICAL, buildTrustAnchors } from "./index";
import * as fs from "fs";

// VICAL 파일 읽기
const vicalBytes = fs.readFileSync("./test.cbor");

// 파싱
const signedVical = parseVICAL(vicalBytes);

console.log(signedVical);

// 기본 정보
console.log(signedVical.vical.version); // "1.0"
console.log(signedVical.vical.vicalProvider); // "Korea VICAL Service"
console.log(signedVical.vical.certificateInfos); // 인증서 개수

// Trust Anchor 맵 생성 (국가별 IACA)
const trustAnchors = buildTrustAnchors(signedVical.vical);
