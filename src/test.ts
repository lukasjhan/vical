import { parseVICAL, buildTrustAnchors } from "./index";
import * as fs from "fs";

const vicalBytes = fs.readFileSync("./test.cbor");
const signedVical = parseVICAL(vicalBytes);

console.log(signedVical);

console.log("Version:", signedVical.vical.version);
console.log("Provider:", signedVical.vical.vicalProvider);
console.log("Certificate count:", signedVical.vical.certificateInfos.length);
console.log("Certificates:", signedVical.vical.certificateInfos);

const trustAnchors = buildTrustAnchors(signedVical.vical);
