// Fixture: criptografía post-cuántica. La acción NO debe marcar NADA de esto.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
// ML-DSA-65 (FIPS 204) para firmas, ML-KEM-768 (FIPS 203) para encapsulado, SHA-256 para hash.
export const sign = (m: Uint8Array, k: Uint8Array) => ml_dsa65.sign(k, m);
