// Fixture: criptografía clásica real. La acción DEBE marcar esto.
const crypto = require('crypto');
const signer = crypto.createSign('RSA-SHA256');
const kex = crypto.createECDH('secp256k1');
const jwt = { alg: 'ES256' };          // ECDSA P-256
const ssh = 'ssh-ed25519 AAAAC3Nz';    // EdDSA
