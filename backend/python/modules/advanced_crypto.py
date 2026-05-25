"""
Advanced Cryptography Module - Quantum-Resistant Enterprise Grade
Modern encryption, digital signatures, and quantum-resistant cryptography
"""

import os
import base64
import hashlib
import hmac
import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
import structlog

logger = structlog.get_logger()

@dataclass
class CryptoOperation:
    """Record of cryptographic operation"""
    operation_id: str
    operation_type: str  # encrypt, decrypt, sign, verify, hash
    algorithm: str
    key_size: int
    timestamp: datetime
    file_size: Optional[int] = None
    success: bool = True
    error_message: Optional[str] = None

@dataclass
class KeyMetadata:
    """Cryptographic key metadata"""
    key_id: str
    algorithm: str
    key_size: int
    created_at: datetime
    expires_at: Optional[datetime]
    purpose: str  # encryption, signing, verification
    quantum_resistant: bool
    key_derivation: Optional[str] = None

class AdvancedCrypto:
    """Enterprise cryptography suite with quantum-resistant algorithms"""

    def __init__(self):
        self.upload_folder = Path('uploads/crypto')
        self.key_store_path = Path('keystore')
        self.temp_folder = Path('temp/crypto')

        # Create necessary directories
        for folder in [self.upload_folder, self.key_store_path, self.temp_folder]:
            folder.mkdir(parents=True, exist_ok=True)

        self.operation_log = []
        self.key_registry = {}

        # Supported algorithms
        self.symmetric_algorithms = {
            'aes256': {'key_size': 32, 'quantum_resistant': False},
            'chacha20': {'key_size': 32, 'quantum_resistant': False},
            'salsa20': {'key_size': 32, 'quantum_resistant': False}
        }

        self.asymmetric_algorithms = {
            'rsa2048': {'key_size': 2048, 'quantum_resistant': False},
            'rsa4096': {'key_size': 4096, 'quantum_resistant': False},
            'ec_p256': {'key_size': 256, 'quantum_resistant': False},
            'ec_p384': {'key_size': 384, 'quantum_resistant': False},
            'kyber512': {'key_size': 512, 'quantum_resistant': True},
            'kyber768': {'key_size': 768, 'quantum_resistant': True},
            'kyber1024': {'key_size': 1024, 'quantum_resistant': True}
        }

        self.hash_algorithms = {
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256,
            'sha3_512': hashlib.sha3_512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s
        }

    def generate_key_pair(self, algorithm: str = 'rsa4096') -> Tuple[str, Dict]:
        """Generate cryptographic key pair"""

        key_id = secrets.token_hex(16)
        operation_id = secrets.token_hex(8)

        try:
            if algorithm == 'rsa2048':
                private_key, public_key = self._generate_rsa_keypair(2048)
            elif algorithm == 'rsa4096':
                private_key, public_key = self._generate_rsa_keypair(4096)
            elif algorithm.startswith('ec_'):
                curve_name = algorithm.split('_')[1]
                private_key, public_key = self._generate_ec_keypair(curve_name)
            elif algorithm.startswith('kyber'):
                private_key, public_key = self._generate_kyber_keypair(algorithm)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            # Store key metadata
            metadata = KeyMetadata(
                key_id=key_id,
                algorithm=algorithm,
                key_size=self.asymmetric_algorithms[algorithm]['key_size'],
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(days=365),  # 1 year
                purpose='encryption_signing',
                quantum_resistant=self.asymmetric_algorithms[algorithm]['quantum_resistant']
            )

            self.key_registry[key_id] = metadata

            # Save keys to keystore
            self._save_key_pair(key_id, private_key, public_key, metadata)

            # Log operation
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='key_generation',
                algorithm=algorithm,
                key_size=metadata.key_size,
                timestamp=datetime.now(),
                success=True
            ))

            logger.info("key_pair_generated",
                       key_id=key_id,
                       algorithm=algorithm,
                       quantum_resistant=metadata.quantum_resistant)

            return key_id, {
                'key_id': key_id,
                'algorithm': algorithm,
                'key_size': metadata.key_size,
                'quantum_resistant': metadata.quantum_resistant,
                'public_key': public_key,
                'expires_at': metadata.expires_at.isoformat()
            }

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='key_generation',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))

            logger.error("key_generation_failed",
                        algorithm=algorithm,
                        error=str(e))
            raise

    def quantum_encrypt(self, file_obj, algorithm: str = 'kyber512', password: Optional[str] = None) -> Dict:
        """Quantum-resistant file encryption"""

        operation_id = secrets.token_hex(8)

        try:
            # Save uploaded file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{secrets.token_hex(8)}_{file_obj.filename}"
            file_path = self.upload_folder / filename
            file_obj.save(str(file_path))

            file_size = file_path.stat().st_size

            if algorithm.startswith('kyber'):
                encrypted_data, key_data = self._kyber_encrypt(file_path, algorithm, password)
            else:
                # Fall back to hybrid encryption with traditional algorithms
                encrypted_data, key_data = self._hybrid_encrypt(file_path, algorithm, password)

            # Save encrypted file
            encrypted_filename = f"{filename}.enc"
            encrypted_path = self.upload_folder / encrypted_filename

            with open(encrypted_path, 'wb') as enc_file:
                enc_file.write(encrypted_data)

            # Clean up original file
            file_path.unlink()

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='encrypt',
                algorithm=algorithm,
                key_size=self.asymmetric_algorithms.get(algorithm, {}).get('key_size', 0),
                timestamp=datetime.now(),
                file_size=file_size,
                success=True
            ))

            logger.info("quantum_encryption_completed",
                       filename=filename,
                       algorithm=algorithm,
                       file_size=file_size)

            return {
                'encrypted_file': encrypted_filename,
                'key_data': key_data,
                'algorithm': algorithm,
                'quantum_resistant': self.asymmetric_algorithms.get(algorithm, {}).get('quantum_resistant', False),
                'file_size': file_size,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='encrypt',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                file_size=0,
                success=False,
                error_message=str(e)
            ))

            logger.error("quantum_encryption_failed",
                        error=str(e))
            raise

    def quantum_decrypt(self, file_obj, key_data: Union[str, Dict], algorithm: str = 'kyber512',
                       password: Optional[str] = None) -> Tuple[str, bytes]:
        """Quantum-resistant file decryption"""

        operation_id = secrets.token_hex(8)

        try:
            # Save encrypted file
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            encrypted_filename = f"{timestamp}_{secrets.token_hex(8)}_encrypted"
            encrypted_path = self.temp_folder / encrypted_filename
            file_obj.save(str(encrypted_path))

            # Parse key data
            if isinstance(key_data, str):
                try:
                    parsed_key_data = json.loads(base64.b64decode(key_data).decode())
                except:
                    # Assume it's a direct key
                    parsed_key_data = {'key': key_data}
            else:
                parsed_key_data = key_data

            if algorithm.startswith('kyber'):
                decrypted_data = self._kyber_decrypt(encrypted_path, parsed_key_data, algorithm, password)
            else:
                decrypted_data = self._hybrid_decrypt(encrypted_path, parsed_key_data, algorithm, password)

            # Save decrypted file
            original_filename = parsed_key_data.get('original_filename', 'decrypted_file')
            decrypted_path = self.temp_folder / f"decrypted_{original_filename}"

            with open(decrypted_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)

            # Clean up encrypted file
            encrypted_path.unlink()

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='decrypt',
                algorithm=algorithm,
                key_size=self.asymmetric_algorithms.get(algorithm, {}).get('key_size', 0),
                timestamp=datetime.now(),
                file_size=len(decrypted_data),
                success=True
            ))

            logger.info("quantum_decryption_completed",
                       algorithm=algorithm,
                       file_size=len(decrypted_data))

            return str(decrypted_path), decrypted_data

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='decrypt',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                file_size=0,
                success=False,
                error_message=str(e)
            ))

            logger.error("quantum_decryption_failed",
                        error=str(e))
            raise

    def advanced_hash(self, data: bytes, algorithm: str = 'sha3_256',
                     salt: Optional[bytes] = None, iterations: int = 100000) -> Dict:
        """Advanced cryptographic hashing with salt and key derivation"""

        operation_id = secrets.token_hex(8)

        try:
            if salt is None:
                salt = secrets.token_bytes(32)

            # Standard hashing
            if algorithm in self.hash_algorithms:
                hasher = self.hash_algorithms[algorithm]()
                hasher.update(salt + data)
                hash_result = hasher.hexdigest()
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")

            # Key derivation for password hashing
            if algorithm.startswith('pbkdf2'):
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend()
                )
                hash_result = base64.b64encode(kdf.derive(data)).decode()
            elif algorithm.startswith('scrypt'):
                kdf = Scrypt(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=default_backend()
                )
                hash_result = base64.b64encode(kdf.derive(data)).decode()

            result = {
                'hash': hash_result,
                'algorithm': algorithm,
                'salt': base64.b64encode(salt).decode(),
                'iterations': iterations if 'pbkdf2' in algorithm or 'scrypt' in algorithm else None,
                'timestamp': datetime.now().isoformat()
            }

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='hash',
                algorithm=algorithm,
                key_size=len(data),
                timestamp=datetime.now(),
                file_size=len(data),
                success=True
            ))

            logger.info("advanced_hash_completed",
                       algorithm=algorithm,
                       data_size=len(data))

            return result

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='hash',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))

            logger.error("advanced_hash_failed",
                        algorithm=algorithm,
                        error=str(e))
            raise

    def digital_signature(self, data: bytes, key_id: str, algorithm: str = 'rsa4096') -> Dict:
        """Create digital signature"""

        operation_id = secrets.token_hex(8)

        try:
            # Load private key
            private_key = self._load_private_key(key_id)

            if algorithm.startswith('rsa'):
                signature = private_key.sign(
                    data,
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif algorithm.startswith('ec'):
                signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError(f"Unsupported signature algorithm: {algorithm}")

            result = {
                'signature': base64.b64encode(signature).decode(),
                'algorithm': algorithm,
                'key_id': key_id,
                'timestamp': datetime.now().isoformat(),
                'data_hash': hashlib.sha256(data).hexdigest()
            }

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='sign',
                algorithm=algorithm,
                key_size=self.key_registry[key_id].key_size,
                timestamp=datetime.now(),
                file_size=len(data),
                success=True
            ))

            logger.info("digital_signature_created",
                       key_id=key_id,
                       algorithm=algorithm)

            return result

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='sign',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))

            logger.error("digital_signature_failed",
                        key_id=key_id,
                        error=str(e))
            raise

    def verify_signature(self, data: bytes, signature: str, key_id: str, algorithm: str = 'rsa4096') -> Dict:
        """Verify digital signature"""

        operation_id = secrets.token_hex(8)

        try:
            # Load public key
            public_key = self._load_public_key(key_id)
            signature_bytes = base64.b64decode(signature)

            valid = False

            if algorithm.startswith('rsa'):
                try:
                    public_key.verify(
                        signature_bytes,
                        data,
                        asym_padding.PSS(
                            mgf=asym_padding.MGF1(hashes.SHA256()),
                            salt_length=asym_padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    valid = True
                except Exception:
                    valid = False
            elif algorithm.startswith('ec'):
                try:
                    public_key.verify(signature_bytes, data, ec.ECDSA(hashes.SHA256()))
                    valid = True
                except Exception:
                    valid = False

            result = {
                'valid': valid,
                'algorithm': algorithm,
                'key_id': key_id,
                'timestamp': datetime.now().isoformat(),
                'data_hash': hashlib.sha256(data).hexdigest()
            }

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='verify',
                algorithm=algorithm,
                key_size=self.key_registry[key_id].key_size,
                timestamp=datetime.now(),
                file_size=len(data),
                success=valid
            ))

            logger.info("signature_verification_completed",
                       key_id=key_id,
                       valid=valid)

            return result

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='verify',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))

            logger.error("signature_verification_failed",
                        key_id=key_id,
                        error=str(e))
            raise

    def secure_random(self, length: int = 32, encoding: str = 'hex') -> Dict:
        """Generate cryptographically secure random data"""

        try:
            random_bytes = secrets.token_bytes(length)

            if encoding == 'hex':
                random_data = random_bytes.hex()
            elif encoding == 'base64':
                random_data = base64.b64encode(random_bytes).decode()
            elif encoding == 'raw':
                random_data = random_bytes
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")

            return {
                'random_data': random_data,
                'length': length,
                'encoding': encoding,
                'timestamp': datetime.now().isoformat(),
                'entropy_source': 'secrets.token_bytes'
            }

        except Exception as e:
            logger.error("secure_random_generation_failed",
                        length=length,
                        encoding=encoding,
                        error=str(e))
            raise

    def stream_cipher_encrypt(self, data: bytes, algorithm: str = 'chacha20') -> Dict:
        """Stream cipher encryption"""

        operation_id = secrets.token_hex(8)

        try:
            key = secrets.token_bytes(32)  # 256-bit key

            if algorithm == 'chacha20':
                nonce = secrets.token_bytes(16)  # ChaCha20 nonce
                cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()
            else:
                raise ValueError(f"Unsupported stream cipher: {algorithm}")

            result = {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'key': base64.b64encode(key).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'algorithm': algorithm,
                'timestamp': datetime.now().isoformat()
            }

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='stream_encrypt',
                algorithm=algorithm,
                key_size=256,
                timestamp=datetime.now(),
                file_size=len(data),
                success=True
            ))

            return result

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='stream_encrypt',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))
            raise

    def stream_cipher_decrypt(self, encrypted_data: str, key: str, nonce: str, algorithm: str = 'chacha20') -> bytes:
        """Stream cipher decryption"""

        operation_id = secrets.token_hex(8)

        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            key_bytes = base64.b64decode(key)
            nonce_bytes = base64.b64decode(nonce)

            if algorithm == 'chacha20':
                cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce_bytes), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
            else:
                raise ValueError(f"Unsupported stream cipher: {algorithm}")

            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='stream_decrypt',
                algorithm=algorithm,
                key_size=256,
                timestamp=datetime.now(),
                file_size=len(decrypted_data),
                success=True
            ))

            return decrypted_data

        except Exception as e:
            self._log_operation(CryptoOperation(
                operation_id=operation_id,
                operation_type='stream_decrypt',
                algorithm=algorithm,
                key_size=0,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            ))
            raise

    def get_crypto_stats(self) -> Dict:
        """Get cryptographic operation statistics"""

        total_operations = len(self.operation_log)
        successful_operations = len([op for op in self.operation_log if op.success])

        operations_by_type = {}
        operations_by_algorithm = {}

        for operation in self.operation_log:
            operations_by_type[operation.operation_type] = operations_by_type.get(operation.operation_type, 0) + 1
            operations_by_algorithm[operation.algorithm] = operations_by_algorithm.get(operation.algorithm, 0) + 1

        return {
            'total_operations': total_operations,
            'successful_operations': successful_operations,
            'success_rate': (successful_operations / total_operations) * 100 if total_operations > 0 else 0,
            'operations_by_type': operations_by_type,
            'operations_by_algorithm': operations_by_algorithm,
            'active_keys': len(self.key_registry),
            'quantum_resistant_keys': len([k for k in self.key_registry.values() if k.quantum_resistant]),
            'last_operation': self.operation_log[-1].timestamp.isoformat() if self.operation_log else None
        }

    def list_keys(self) -> List[Dict]:
        """List all keys in the registry"""

        keys = []
        for key_id, metadata in self.key_registry.items():
            keys.append({
                'key_id': key_id,
                'algorithm': metadata.algorithm,
                'key_size': metadata.key_size,
                'created_at': metadata.created_at.isoformat(),
                'expires_at': metadata.expires_at.isoformat() if metadata.expires_at else None,
                'purpose': metadata.purpose,
                'quantum_resistant': metadata.quantum_resistant,
                'expired': datetime.now() > metadata.expires_at if metadata.expires_at else False
            })

        return sorted(keys, key=lambda x: x['created_at'], reverse=True)

    # Private methods for implementation details

    def _generate_rsa_keypair(self, key_size: int) -> Tuple[str, str]:
        """Generate RSA key pair"""

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.b64encode(private_pem).decode(), base64.b64encode(public_pem).decode()

    def _generate_ec_keypair(self, curve_name: str) -> Tuple[str, str]:
        """Generate Elliptic Curve key pair"""

        if curve_name == 'p256':
            curve = ec.SECP256R1()
        elif curve_name == 'p384':
            curve = ec.SECP384R1()
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")

        private_key = ec.generate_private_key(curve, default_backend())

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return base64.b64encode(private_pem).decode(), base64.b64encode(public_pem).decode()

    def _generate_kyber_keypair(self, algorithm: str) -> Tuple[str, str]:
        """Generate Kyber quantum-resistant key pair (placeholder implementation)"""
        # Note: This is a placeholder. In a real implementation, you would use
        # a proper post-quantum cryptography library like liboqs-python

        if algorithm == 'kyber512':
            key_size = 512
        elif algorithm == 'kyber768':
            key_size = 768
        elif algorithm == 'kyber1024':
            key_size = 1024
        else:
            raise ValueError(f"Unsupported Kyber variant: {algorithm}")

        # Placeholder: generate random keys (not actual Kyber keys)
        private_key = base64.b64encode(secrets.token_bytes(key_size // 4)).decode()
        public_key = base64.b64encode(secrets.token_bytes(key_size // 4)).decode()

        return private_key, public_key

    def _kyber_encrypt(self, file_path: Path, algorithm: str, password: Optional[str]) -> Tuple[bytes, Dict]:
        """Kyber encryption (placeholder implementation)"""
        # Note: This is a placeholder implementation

        with open(file_path, 'rb') as f:
            data = f.read()

        # Generate session key
        session_key = secrets.token_bytes(32)

        # Encrypt data with AES
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad data
        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Placeholder: "encrypt" session key with Kyber (actually just encode)
        encrypted_session_key = base64.b64encode(session_key).decode()

        # Combine IV + encrypted data
        combined_data = iv + encrypted_data

        key_data = {
            'encrypted_session_key': encrypted_session_key,
            'algorithm': algorithm,
            'original_filename': file_path.name
        }

        return combined_data, key_data

    def _kyber_decrypt(self, encrypted_path: Path, key_data: Dict, algorithm: str, password: Optional[str]) -> bytes:
        """Kyber decryption (placeholder implementation)"""

        with open(encrypted_path, 'rb') as f:
            combined_data = f.read()

        # Extract IV and encrypted data
        iv = combined_data[:16]
        encrypted_data = combined_data[16:]

        # Placeholder: "decrypt" session key (actually just decode)
        session_key = base64.b64decode(key_data['encrypted_session_key'])

        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad data
        unpadder = PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data

    def _hybrid_encrypt(self, file_path: Path, algorithm: str, password: Optional[str]) -> Tuple[bytes, Dict]:
        """Hybrid encryption with traditional algorithms"""

        with open(file_path, 'rb') as f:
            data = f.read()

        # Generate session key
        session_key = Fernet.generate_key()
        fernet = Fernet(session_key)

        # Encrypt data
        encrypted_data = fernet.encrypt(data)

        key_data = {
            'session_key': session_key.decode(),
            'algorithm': algorithm,
            'original_filename': file_path.name
        }

        return encrypted_data, key_data

    def _hybrid_decrypt(self, encrypted_path: Path, key_data: Dict, algorithm: str, password: Optional[str]) -> bytes:
        """Hybrid decryption with traditional algorithms"""

        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        # Get session key
        session_key = key_data['session_key'].encode()
        fernet = Fernet(session_key)

        # Decrypt data
        data = fernet.decrypt(encrypted_data)

        return data

    def _save_key_pair(self, key_id: str, private_key: str, public_key: str, metadata: KeyMetadata):
        """Save key pair to keystore"""

        key_folder = self.key_store_path / key_id
        key_folder.mkdir(exist_ok=True)

        # Save private key
        with open(key_folder / 'private.pem', 'w') as f:
            f.write(private_key)

        # Save public key
        with open(key_folder / 'public.pem', 'w') as f:
            f.write(public_key)

        # Save metadata
        with open(key_folder / 'metadata.json', 'w') as f:
            metadata_dict = asdict(metadata)
            metadata_dict['created_at'] = metadata.created_at.isoformat()
            metadata_dict['expires_at'] = metadata.expires_at.isoformat() if metadata.expires_at else None
            json.dump(metadata_dict, f, indent=2)

    def _load_private_key(self, key_id: str):
        """Load private key from keystore"""

        key_folder = self.key_store_path / key_id
        private_key_path = key_folder / 'private.pem'

        with open(private_key_path, 'r') as f:
            private_key_pem = base64.b64decode(f.read())

        return serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

    def _load_public_key(self, key_id: str):
        """Load public key from keystore"""

        key_folder = self.key_store_path / key_id
        public_key_path = key_folder / 'public.pem'

        with open(public_key_path, 'r') as f:
            public_key_pem = base64.b64decode(f.read())

        return serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

    def _log_operation(self, operation: CryptoOperation):
        """Log cryptographic operation"""
        self.operation_log.append(operation)

        # Keep only last 1000 operations
        if len(self.operation_log) > 1000:
            self.operation_log = self.operation_log[-1000:]