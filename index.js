const crypto = require('crypto');
const secp256k1 = require('secp256k1');

const alicetext_true = process.argv[2];
const alicetext_false = 'warning';

if (!alicetext_true || !alicetext_true.trim().length) {
	console.log('Вы должны написать текст после команды');
}

const alicetext_true_digest = getDigest(alicetext_true);
const alicetext_false_digest = getDigest(alicetext_false);

console.log(`	0) Alice's message: 
	message: ${alicetext_true}
	message digest true: ${alicetext_true_digest.toString("hex")}

	message_false: ${alicetext_false}
	message digest false: ${alicetext_false_digest.toString("hex")}
	`);

/*
generate privateKey
*/
let privateKey;

do {
    privateKey = crypto.randomBytes(32);
} while (!secp256k1.privateKeyVerify(privateKey));


const publicKey = secp256k1.publicKeyCreate(privateKey);

console.log(`	1) Alice aquired new keypair:
	publicKey: ${Buffer.from(publicKey).toString("hex")}
	privateKey: ${privateKey.toString("hex")}
	`);

/*
 Sign the message
*/
console.log(`	2) Alice signed her message digest with her privateKey to get its signature:`);
const sigObj = secp256k1.ecdsaSign(alicetext_true_digest, privateKey);
const sig = sigObj.signature;
console.log("	Signature:", Buffer.from(sig).toString("hex"));

/*
 Verify
*/
console.log(`
	3) Bob verifyed by 3 elements ("message digest", "signature", and Alice's "publicKey"):`);
let verified_true = secp256k1.ecdsaVerify(sig, alicetext_true_digest, publicKey);
console.log("	verified_true:", verified_true);

let verified_false = secp256k1.ecdsaVerify(sig, alicetext_false_digest, publicKey);
console.log("	verified_false:", verified_false);


function getDigest(str, algo = "sha256") {
  return crypto.createHash(algo).update(str).digest();
}
