# Paso 27: PURGA de la cripto legada. Este módulo contenía el cifrado v1 del servidor
# (AES-CFB/ChaCha20 sin AEAD → C6, PBKDF2 100k → A8, capa Fernet → M2) y `decrypt_password`, que
# hacían al servidor capaz de descifrar (C1). Todo eso se eliminó: en v2 el cifrado ocurre en el
# cliente (crypto.ts) y el servidor sólo maneja blobs opacos.
#
# Sobrevive únicamente `generate_passwords`, un generador con CSPRNG (`secrets.randbelow`, correcto)
# que sigue teniendo un consumidor vivo (general_views.api_password_generator). No es cripto de
# cifrado: es generación de contraseñas.

import string
import secrets


def generate_passwords(ammount: int, length: int, symbols: bool, uppercase: bool):
    passwords = []
    for _ in range(ammount):
        combination = string.ascii_lowercase + string.digits

        if symbols:
            combination += string.punctuation

        if uppercase:
            combination += string.ascii_uppercase

        combination_length = len(combination)
        password = ''
        for _ in range(length):
            password += combination[secrets.randbelow(combination_length)]

        passwords.append(password)

    return passwords
