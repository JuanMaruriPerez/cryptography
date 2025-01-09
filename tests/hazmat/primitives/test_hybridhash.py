import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.khf.hybridhash import HybridHASH

class TestHybridHASH:
    @pytest.fixture
    def kdf_sha256_concat_32b(self):
        """Fixture para SHA256 con concatenación y longitud de 32 bytes."""
        salt = b"my_salt"
        key_material1 = b"hello"
        key_material2 = b"world"
        hash_algorithm = hashes.SHA256()
        return HybridHASH(hash_algorithm, key_material1, key_material2, 32, salt, operation="concat")

    @pytest.fixture
    def kdf_sha256_concat_16b(self):
        """Fixture para SHA256 con concatenación y longitud de 16 bytes."""
        salt = b"my_salt"
        key_material1 = b"hello"
        key_material2 = b"world"
        hash_algorithm = hashes.SHA256()
        return HybridHASH(hash_algorithm, key_material1, key_material2, 16, salt, operation="concat")

    @pytest.fixture
    def kdf_sha256_xor(self):
        """Fixture para SHA256 con XOR (key_material1 y key_material2 deben ser del mismo tamaño)."""
        salt = b"my_salt"
        key_material1 = b"abcde"
        key_material2 = b"12345"  # Misma longitud que key_material1
        hash_algorithm = hashes.SHA256()
        return HybridHASH(hash_algorithm, key_material1, key_material2, 32, salt, operation="xor")

    def test_derive_concat_32b(self, kdf_sha256_concat_32b: HybridHASH):
        # Derivar la clave de 32 bytes con concatenación
        derived_key = kdf_sha256_concat_32b.derive()
        assert len(derived_key) == 32

    def test_derive_concat_16b(self, kdf_sha256_concat_16b: HybridHASH):
        # Derivar la clave de 16 bytes con concatenación
        derived_key = kdf_sha256_concat_16b.derive()
        assert len(derived_key) == 16

    def test_derive_xor(self, kdf_sha256_xor: HybridHASH):
        # Derivar la clave de 32 bytes con XOR
        derived_key = kdf_sha256_xor.derive()
        assert len(derived_key) == 32

    def test_error_xor_different_lengths(self):
        """Prueba que se lanza un error si las longitudes de key_material1 y key_material2 no coinciden para XOR."""
        hash_algorithm = hashes.SHA256()
        key_material1 = b"short"
        key_material2 = b"longer"
        with pytest.raises(ValueError, match="Las cadenas key_material1 y key_material2 deben tener la misma longitud para la operación XOR."):
            HybridHASH(hash_algorithm, key_material1, key_material2, 32, operation="xor")

    def test_derive_error_on_large_length(self):
        """Prueba que no se pueda derivar una clave más grande que el tamaño máximo permitido."""
        hash_algorithm = hashes.SHA256()
        max_length = hash_algorithm.digest_size
        with pytest.raises(ValueError, match=f"Requested length exceeds the maximum length of {max_length} bytes"):
            HybridHASH(hash_algorithm, b"hello", b"world", max_length + 1, b"my_salt", operation="concat").derive()

    def test_invalid_operation(self):
        """Prueba que se lanza un error si se especifica una operación inválida."""
        hash_algorithm = hashes.SHA256()
        with pytest.raises(ValueError, match="La operación debe ser 'concat' o 'xor'."):
            HybridHASH(hash_algorithm, b"hello", b"world", 32, b"my_salt", operation="unknown")
