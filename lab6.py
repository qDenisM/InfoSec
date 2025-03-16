from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
import os
import random

# Функция для измерения времени выполнения
def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"{func.__name__} выполнено за {end_time - start_time:.4f} секунд")
        return result
    return wrapper

# 1. RSA
@measure_time
def rsa_example():
    # Генерация ключей
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    message = b"Secret message for RSA"

    # Шифрование
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    # Дешифрование
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return plaintext == message

# 2. Diffie-Hellman
@measure_time
def diffie_hellman_example():
    # Параметры
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key_a = parameters.generate_private_key()
    public_key_a = private_key_a.public_key()
    private_key_b = parameters.generate_private_key()
    public_key_b = private_key_b.public_key()

    # Общий секрет для первого пользователя
    shared_key_a = private_key_a.exchange(public_key_b)
    # Общий секрет для второго пользователя
    shared_key_b = private_key_b.exchange(public_key_a)

    return shared_key_a == shared_key_b

# 3. ElGamal
# Класс для реализации Эль-Гамаля
class ElGamal:
    def __init__(self, key_size=2048):
        # Генерация чисел
        parameters = dh.generate_parameters(generator=2, key_size=key_size)
        self.p = parameters.parameter_numbers().p
        self.g = parameters.parameter_numbers().g

    def generate_keys(self):
        # Генерация секретного ключа x и открытого ключа h
        self.x = int.from_bytes(os.urandom(32), 'big') % (self.p - 2) + 1  # Случайное x от 1 до p-2
        self.h = pow(self.g, self.x, self.p)
        return self.h

    def encrypt(self, message):
        m = int.from_bytes(message.encode('utf-8'), 'big') % self.p
        if m == 0:
            m = 1

        # Случайный ключ k
        k = int.from_bytes(os.urandom(32), 'big') % (self.p - 2) + 1

        # Шифрование: c1, c2
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.h, k, self.p)) % self.p

        return (c1, c2)

    def decrypt(self, ciphertext):
        c1, c2 = ciphertext

        # Дешифрование
        s = pow(c1, self.x, self.p)
        s_inv = pow(s, self.p - 2, self.p)
        m = (c2 * s_inv) % self.p

        byte_length = (m.bit_length() + 7) // 8
        m_bytes = m.to_bytes(byte_length, 'big')
        try:
            return m_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return m

@measure_time
def elgamal_example():
    # Инициализация
    elgamal = ElGamal(key_size=2048)
    public_key = elgamal.generate_keys()

    # Сообщение
    message = "Secret ElGamal message"

    # Шифрование
    ciphertext = elgamal.encrypt(message)

    # Дешифрование
    decrypted = elgamal.decrypt(ciphertext)

    return message == decrypted

# Запуск и анализ
print("Запуск тестов...\n")
print("RSA:", "Успех" if rsa_example() else "Ошибка")
print("Diffie-Hellman:", "Успех" if diffie_hellman_example() else "Ошибка")
print("ElGamal:", "Успех" if elgamal_example() else "Ошибка")
print("Конец тестов.")
