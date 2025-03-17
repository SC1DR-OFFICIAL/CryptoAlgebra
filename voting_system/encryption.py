from phe import paillier


def generate_homomorphic_keypair():
    """Генерация ключей шифрования Paillier"""
    public_key, private_key = paillier.generate_paillier_keypair()
    return public_key, private_key


def serialize_private_key(private_key):
    """Сохранение приватного ключа в строку"""
    return f"{private_key.p}:{private_key.q}"  # Используем p и q


def deserialize_private_key(serialized_key, public_key):
    """Восстановление приватного ключа из строки"""
    p, q = serialized_key.split(':')
    return paillier.PaillierPrivateKey(public_key, int(p), int(q))  # Используем p и q

