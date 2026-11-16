"""Hasher de contraseñas del proyecto: Argon2id con parámetros fijos."""

from django.contrib.auth.hashers import Argon2PasswordHasher

# Configuración mínima recomendada por OWASP para Argon2id.
ARGON2_TIEMPO = 2
ARGON2_MEMORIA_KIB = 19456
ARGON2_PARALELISMO = 1


class Argon2idHasher(Argon2PasswordHasher):
    """Argon2id (m=19456 KiB, t=2, p=1). Conserva el algoritmo "argon2" del formato de Django."""

    time_cost = ARGON2_TIEMPO
    memory_cost = ARGON2_MEMORIA_KIB
    parallelism = ARGON2_PARALELISMO
