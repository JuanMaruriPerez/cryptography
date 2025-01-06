import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.khf.hybridhash import HybridHASH

class TestHybridHASH:
    @pytest.fixture
    def kdf_sha256_32b(self):
        """Fixture para SHA256 con longitud de 32 bytes."""
        salt = b"my_salt"
        key_material1 = b"hello"
        key_material2 = b"world"
        hash_algorithm = hashes.SHA256()  # Usar la instancia del algoritmo
        return HybridHASH(hash_algorithm, key_material1, key_material2, 32, salt)

    @pytest.fixture
    def kdf_sha256_16b(self):
        """Fixture para SHA256 con longitud de 16 bytes."""
        salt = b"my_salt"
        key_material1 = b"hello"
        key_material2 = b"world"
        hash_algorithm = hashes.SHA256()  # Usar la instancia del algoritmo
        return HybridHASH(hash_algorithm, key_material1, key_material2, 16, salt)

    def test_derive_32b(self, kdf_sha256_32b: HybridHASH):
        # Derivar la clave de 32 bytes
        derived_key = kdf_sha256_32b.derive()

        print(f"Derived key (32 bytes): {derived_key}")

        # Verificar que la clave derivada es consistente
        expected_derived_key = kdf_sha256_32b.derive()  # Debería ser el mismo valor
        print(f"Expected derived key (32 bytes): {expected_derived_key}")

        # Asegurarse de que la longitud de la clave derivada sea de 32 bytes
        assert len(derived_key) == 32
        assert derived_key == expected_derived_key

    def test_derive_16b(self, kdf_sha256_16b: HybridHASH):
        # Derivar la clave de 16 bytes
        derived_key = kdf_sha256_16b.derive()

        print(f"Derived key (16 bytes): {derived_key}")

        # Verificar que la clave derivada es consistente
        expected_derived_key = kdf_sha256_16b.derive()  # Debería ser el mismo valor
        print(f"Expected derived key (16 bytes): {expected_derived_key}")

        # Asegurarse de que la longitud de la clave derivada sea de 16 bytes
        assert len(derived_key) == 16
        assert derived_key == expected_derived_key

    def test_derive_error_on_large_length(self):
        """Prueba que no se pueda derivar una clave más grande que el tamaño máximo permitido."""
        hash_algorithm = hashes.SHA256()  # Usar la instancia del algoritmo
        max_length = hash_algorithm.digest_size  # Obtener el tamaño máximo en bytes (32 para SHA256)

        print(f"Verificando que no se pueda derivar una clave mayor que {max_length} bytes...")

        # Se asegura que si se pide una longitud mayor a 32 bytes, se lanza el error correspondiente
        with pytest.raises(ValueError, match=r"Requested length exceeds the maximum length of 32 bytes"):
            HybridHASH(hash_algorithm, b"hello", b"world", max_length + 1, b"my_salt").derive()

        # Si llegamos aquí, significa que el error fue capturado como se esperaba
        print("El error esperado fue lanzado correctamente.")