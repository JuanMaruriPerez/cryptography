import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.khf.hybridhmac import HybridHMAC

class TestHybridHMAC:

    @pytest.fixture
    def setup(self):
        # Material de claves para las pruebas
        self.key_material1 = b"clave1"
        self.key_material2 = b"clave2"
        self.salt = b"salto"
        self.secret_key = b"clave_secreta"
        self.algorithm = hashes.SHA256()
        self.length = 32  # Longitud deseada de la clave derivada
        return self

    def test_concat_operation(self, setup):
        # Probar operación 'concat'
        hybrid_hmac = HybridHMAC(
            algorithm=setup.algorithm,
            key_material1=setup.key_material1,
            key_material2=setup.key_material2,
            length=setup.length,
            salt=setup.salt,
            operation="concat",
            secret_key=setup.secret_key
        )
        
        derived_key = hybrid_hmac.derive()
        assert len(derived_key) == setup.length, f"Se esperaba una clave derivada de longitud {setup.length}, pero se obtuvo una de longitud {len(derived_key)}."
        
        # Verificar que la clave derivada sea la misma
        hybrid_hmac.verify(derived_key)

    def test_xor_operation(self, setup):
        # Probar operación 'xor'
        hybrid_hmac = HybridHMAC(
            algorithm=setup.algorithm,
            key_material1=setup.key_material1,
            key_material2=setup.key_material2,
            length=setup.length,
            salt=setup.salt,
            operation="xor",
            secret_key=setup.secret_key
        )
        
        derived_key = hybrid_hmac.derive()
        assert len(derived_key) == setup.length, f"Se esperaba una clave derivada de longitud {setup.length}, pero se obtuvo una de longitud {len(derived_key)}."
        
        # Verificar que la clave derivada sea la misma
        hybrid_hmac.verify(derived_key)

    def test_default_secret_key(self, setup):
        # Probar con clave secreta por defecto (cadena vacía)
        hybrid_hmac = HybridHMAC(
            algorithm=setup.algorithm,
            key_material1=setup.key_material1,
            key_material2=setup.key_material2,
            length=setup.length,
            salt=setup.salt,
            operation="concat",  # Puedes probar también "xor"
            secret_key=None  # Deja el valor por defecto
        )
        
        derived_key = hybrid_hmac.derive()
        assert len(derived_key) == setup.length, f"Se esperaba una clave derivada de longitud {setup.length}, pero se obtuvo una de longitud {len(derived_key)}."
        
        # Verificar que la clave derivada sea la misma
        hybrid_hmac.verify(derived_key)

    def test_invalid_key_length(self, setup):
        # Probar cuando la longitud solicitada supera el tamaño del hash
        with pytest.raises(ValueError, match=f"Requested length exceeds the maximum length of {setup.algorithm.digest_size} bytes"):
            HybridHMAC(
                algorithm=setup.algorithm,
                key_material1=setup.key_material1,
                key_material2=setup.key_material2,
                length=setup.algorithm.digest_size + 1,  # Longitud mayor a la máxima
                salt=setup.salt,
                operation="concat",
                secret_key=setup.secret_key
            )

    def test_invalid_operation(self, setup):
        # Probar operación no válida
        with pytest.raises(ValueError, match="La operación debe ser 'concat' o 'xor'."):
            HybridHMAC(
                algorithm=setup.algorithm,
                key_material1=setup.key_material1,
                key_material2=setup.key_material2,
                length=setup.length,
                salt=setup.salt,
                operation="invalid",  # Operación no válida
                secret_key=setup.secret_key
            )

    def test_mismatched_key_material_for_xor(self, setup):
        # Probar que la longitud de las claves debe coincidir para la operación XOR
        with pytest.raises(ValueError, match="Las cadenas key_material1 y key_material2 deben tener la misma longitud para la operación XOR."):
            HybridHMAC(
                algorithm=setup.algorithm,
                key_material1=setup.key_material1,
                key_material2=b"corta",  # Clave más corta
                length=setup.length,
                salt=setup.salt,
                operation="xor",
                secret_key=setup.secret_key
            )

    def test_key_verification_fail(self, setup):
        # Probar que la verificación falle cuando la clave derivada no coincide
        hybrid_hmac = HybridHMAC(
            algorithm=setup.algorithm,
            key_material1=setup.key_material1,
            key_material2=setup.key_material2,
            length=setup.length,
            salt=setup.salt,
            operation="concat",
            secret_key=setup.secret_key
        )
        
        # Modificar la clave derivada para que no coincida
        wrong_key = b"wrong" * 8  # Clave incorrecta de longitud 32
        with pytest.raises(InvalidKey, match="The key is invalid."):
            hybrid_hmac.verify(wrong_key)
