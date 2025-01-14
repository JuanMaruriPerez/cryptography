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
        operation: str = "concat" # Concatenacion como default operation
    ):
        # Verificar que `algorithm` es una instancia de `HashAlgorithm`
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise ValueError("El algoritmo debe ser una instancia válida de HashAlgorithm.")

        self._algorithm = algorithm  # Usar el algoritmo como una instancia de hashes.Hash
        self._key_material1 = key_material1
        self._key_material2 = key_material2
        self._length = length
        self._operation = operation.lower()

        # Verifica que la longitud no supere el tamaño máximo del hash
        if length > self._algorithm.digest_size:
            raise ValueError(f"Requested length exceeds the maximum length of {self._algorithm.digest_size} bytes")

        # Si no se pasa un salt, usar uno por defecto
        if salt is None:
            salt = b"" 
        self._salt = salt

        # Comprobar operacion soportada
        if self._operation not in ["concat", "xor"]:
            raise ValueError("La operación debe ser 'concat' o 'xor'.")

        # XOR se hace con cadenas de la misma longitud
        if operation == "xor" and len(key_material1) != len(key_material2):
            raise ValueError("Las cadenas key_material1 y key_material2 deben tener la misma longitud para la operación XOR.")

    # Operacion simple de combinacion de cadenas y salt
    def _apply_operation(self) -> bytes:
            if self._operation == "concat":
                # Concatenar key_material1 || salt || key_material2
                return self._key_material1 + self._salt + self._key_material2
            elif self._operation == "xor":
                # Asegurarse de que key_material1 y key_material2 tengan la misma longitud
                min_length = min(len(self._key_material1), len(self._key_material2))
                xor_result = bytes(
                    a ^ b for a, b in zip(self._key_material1[:min_length], self._key_material2[:min_length])
                )
                # Se concatena salt al resultado de la operacion salt
                return xor_result + self._salt
            else:
                raise ValueError("Operación desconocida.")


    # Operar material criptografico
    def derive(self) -> bytes:
        data = self._apply_operation()
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
