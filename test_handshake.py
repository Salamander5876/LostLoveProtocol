#!/usr/bin/env python3
"""
Простой тестовый сервер для проверки handshake протокола LLP
"""

import socket
import struct
import hashlib
import hmac
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HOST = '127.0.0.1'
PORT = 8443

def hex_dump(data, label=""):
    """Выводит hex dump данных"""
    print(f"\n{label} ({len(data)} bytes):")
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  {i:04x}: {hex_str:<48} {ascii_str}")

def main():
    # Генерируем серверную X25519 ключевую пару
    server_private_key = x25519.X25519PrivateKey.generate()
    server_public_key = server_private_key.public_key()
    server_public_bytes = server_public_key.public_bytes_raw()

    print(f"[+] Server X25519 public key: {server_public_bytes.hex()}")

    # Создаём TCP сервер
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"[*] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            print(f"\n[+] Connection from {addr}")

            try:
                # Читаем CLIENT_HELLO (67 bytes)
                client_hello = conn.recv(1024)
                hex_dump(client_hello, "CLIENT_HELLO")

                if len(client_hello) < 67:
                    print(f"[!] CLIENT_HELLO too short: {len(client_hello)} < 67")
                    conn.close()
                    continue

                # Парсим CLIENT_HELLO
                msg_type = client_hello[0]
                client_public_key = client_hello[1:33]
                client_random = client_hello[33:65]
                profile_id = struct.unpack('>H', client_hello[65:67])[0]

                print(f"[+] Message type: {msg_type}")
                print(f"[+] Client public key: {client_public_key.hex()}")
                print(f"[+] Client random: {client_random.hex()}")
                print(f"[+] Profile ID: {profile_id}")

                if msg_type != 1:
                    print(f"[!] Expected CLIENT_HELLO (1), got {msg_type}")
                    conn.close()
                    continue

                # Выполняем X25519 DH
                client_public_key_obj = x25519.X25519PublicKey.from_public_bytes(client_public_key)
                shared_secret = server_private_key.exchange(client_public_key_obj)
                print(f"[+] Shared secret: {shared_secret.hex()}")

                # Генерируем server_random и session_id
                server_random = os.urandom(32)
                session_id = struct.unpack('>Q', os.urandom(8))[0]

                print(f"[+] Server random: {server_random.hex()}")
                print(f"[+] Session ID: {session_id:016x}")

                # HKDF деривация session key
                salt = client_random + server_random
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    info=b"llp-session-key-v1"
                )
                session_key = hkdf.derive(shared_secret)
                print(f"[+] Session key: {session_key.hex()}")

                # Формируем SERVER_HELLO (73 bytes)
                server_hello = bytearray()
                server_hello.append(2)  # Message type
                server_hello.extend(server_public_bytes)
                server_hello.extend(server_random)
                server_hello.extend(struct.pack('>Q', session_id))

                hex_dump(bytes(server_hello), "SERVER_HELLO")
                conn.sendall(server_hello)
                print("[+] Sent SERVER_HELLO")

                # Ждём CLIENT_VERIFY (33 bytes)
                client_verify = conn.recv(1024)
                hex_dump(client_verify, "CLIENT_VERIFY")

                if len(client_verify) < 33:
                    print(f"[!] CLIENT_VERIFY too short: {len(client_verify)} < 33")
                    conn.close()
                    continue

                # Проверяем HMAC
                msg_type = client_verify[0]
                client_hmac = client_verify[1:33]

                if msg_type != 3:
                    print(f"[!] Expected CLIENT_VERIFY (3), got {msg_type}")
                    conn.close()
                    continue

                # Строим транскрипт
                transcript = client_hello + server_hello
                expected_hmac = hmac.new(session_key, transcript, hashlib.sha256).digest()

                print(f"[+] Client HMAC: {client_hmac.hex()}")
                print(f"[+] Expected HMAC: {expected_hmac.hex()}")

                if client_hmac != expected_hmac:
                    print("[!] HMAC verification FAILED!")
                    conn.close()
                    continue

                print("[+] HMAC verification OK!")

                # Отправляем SERVER_VERIFY (33 bytes)
                server_hmac = hmac.new(session_key, transcript, hashlib.sha256).digest()
                server_verify = bytearray()
                server_verify.append(4)  # Message type
                server_verify.extend(server_hmac)

                hex_dump(bytes(server_verify), "SERVER_VERIFY")
                conn.sendall(server_verify)
                print("[+] Sent SERVER_VERIFY")

                print("[+] Handshake COMPLETED!")
                print("[+] Waiting for data...")

                # Ждём дальнейшие данные
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    hex_dump(data, "Received data")

            except Exception as e:
                print(f"[!] Error: {e}")
                import traceback
                traceback.print_exc()
            finally:
                conn.close()
                print("[*] Connection closed")

if __name__ == '__main__':
    main()
