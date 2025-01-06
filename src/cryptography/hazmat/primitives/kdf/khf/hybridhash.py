from typing import Union
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf import KeyDerivationFunction

class HybridHASH(KeyDerivationFunction):
    def __init__(
        self,
        algorithm: hashes.HashAlgorithm,
        key_material1: bytes,
        key_material2: bytes,
        length: int,
        salt: Union[bytes, None] = None,
    ):
        # Verificar que `algorithm` es una instancia de `HashAlgorithm`
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise ValueError("El algoritmo debe ser una instancia válida de HashAlgorithm.")

        self._algorithm = algorithm  # Usar el algoritmo como una instancia de hashes.Hash
        self._key_material1 = key_material1
        self._key_material2 = key_material2
        self._length = length

        # Verifica que la longitud no supere el tamaño máximo del hash
        if length > self._algorithm.digest_size:
            raise ValueError(f"Requested length exceeds the maximum length of {self._algorithm.digest_size} bytes")

        # Si no se pasa un salt, usar uno por defecto
        if salt is None:
            salt = b"\x00" * self._algorithm.block_size  # Default salt if none provided
        self._salt = salt

    def derive(self) -> bytes:
        # Concatenar key_material1 || salt || key_material2
        data = self._key_material1 + self._salt + self._key_material2
        # Aplicar hash sobre la concatenación
        hash_obj = hashes.Hash(self._algorithm)
        hash_obj.update(data)
        derived_key = hash_obj.finalize()

        # Truncar a la longitud deseada
        return derived_key[:self._length]

    def verify(self, expected_key: bytes) -> None:
        derived_key = self.derive()
        if derived_key != expected_key:
            raise InvalidKey("The key is invalid.")