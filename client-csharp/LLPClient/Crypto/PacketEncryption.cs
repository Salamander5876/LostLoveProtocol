using System.Security.Cryptography;

namespace LLPClient.Crypto;

/// <summary>
/// ChaCha20-Poly1305 AEAD шифрование для VPN пакетов
/// </summary>
public class PacketEncryption
{
    private const int CHACHA20_KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;
    private const int TAG_SIZE = 16;

    private readonly byte[] _sessionKey;
    private readonly ulong _sessionId;
    private ulong _sendCounter = 0;
    private ulong _receiveCounter = 0;

    public PacketEncryption(byte[] sessionKey, ulong sessionId)
    {
        if (sessionKey.Length != CHACHA20_KEY_SIZE)
            throw new ArgumentException($"Session key must be {CHACHA20_KEY_SIZE} bytes");

        _sessionKey = sessionKey;
        _sessionId = sessionId;
    }

    /// <summary>
    /// Шифрует IP пакет
    /// Формат: [length:u32][nonce:12][encrypted_data][tag:16]
    /// </summary>
    public byte[] Encrypt(byte[] plaintext)
    {
        // Генерируем nonce: counter(8) || session_id(4)
        var nonce = BuildNonce(_sendCounter++);

        // ChaCha20-Poly1305 шифрование
        using var cipher = new ChaCha20Poly1305(_sessionKey);

        // Выходной буфер: ciphertext + tag
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TAG_SIZE];

        cipher.Encrypt(nonce, plaintext, ciphertext, tag);

        // Формируем финальный пакет: [length:u32][nonce:12][ciphertext][tag:16]
        var packet = new byte[4 + NONCE_SIZE + ciphertext.Length + TAG_SIZE];
        var offset = 0;

        // Length (big-endian u32)
        var lengthBytes = BitConverter.GetBytes((uint)(NONCE_SIZE + ciphertext.Length + TAG_SIZE));
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);
        Array.Copy(lengthBytes, 0, packet, offset, 4);
        offset += 4;

        // Nonce
        Array.Copy(nonce, 0, packet, offset, NONCE_SIZE);
        offset += NONCE_SIZE;

        // Ciphertext
        Array.Copy(ciphertext, 0, packet, offset, ciphertext.Length);
        offset += ciphertext.Length;

        // Tag
        Array.Copy(tag, 0, packet, offset, TAG_SIZE);

        return packet;
    }

    /// <summary>
    /// Дешифрует IP пакет
    /// </summary>
    public byte[]? Decrypt(byte[] packet)
    {
        if (packet.Length < 4 + NONCE_SIZE + TAG_SIZE)
            return null;

        var offset = 0;

        // Читаем length (big-endian u32)
        var lengthBytes = new byte[4];
        Array.Copy(packet, offset, lengthBytes, 0, 4);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);
        var length = BitConverter.ToUInt32(lengthBytes, 0);
        offset += 4;

        if (packet.Length < 4 + length)
            return null;

        // Читаем nonce
        var nonce = new byte[NONCE_SIZE];
        Array.Copy(packet, offset, nonce, 0, NONCE_SIZE);
        offset += NONCE_SIZE;

        // Читаем ciphertext
        var ciphertextLen = (int)length - NONCE_SIZE - TAG_SIZE;
        if (ciphertextLen < 0)
            return null;

        var ciphertext = new byte[ciphertextLen];
        Array.Copy(packet, offset, ciphertext, 0, ciphertextLen);
        offset += ciphertextLen;

        // Читаем tag
        var tag = new byte[TAG_SIZE];
        Array.Copy(packet, offset, tag, 0, TAG_SIZE);

        try
        {
            // ChaCha20-Poly1305 дешифрование
            using var cipher = new ChaCha20Poly1305(_sessionKey);
            var plaintext = new byte[ciphertextLen];

            cipher.Decrypt(nonce, ciphertext, tag, plaintext);

            _receiveCounter++;
            return plaintext;
        }
        catch (CryptographicException)
        {
            // Расшифровка не удалась (неправильный tag или повреждённые данные)
            return null;
        }
    }

    /// <summary>
    /// Строит nonce для ChaCha20-Poly1305
    /// Формат: [counter:8][session_id:4]
    /// </summary>
    private byte[] BuildNonce(ulong counter)
    {
        var nonce = new byte[NONCE_SIZE];

        // Counter (8 bytes, little-endian)
        var counterBytes = BitConverter.GetBytes(counter);
        Array.Copy(counterBytes, 0, nonce, 0, 8);

        // Session ID (4 bytes, lower 32 bits, little-endian)
        var sessionIdBytes = BitConverter.GetBytes((uint)(_sessionId & 0xFFFFFFFF));
        Array.Copy(sessionIdBytes, 0, nonce, 8, 4);

        return nonce;
    }

    public ulong SendCounter => _sendCounter;
    public ulong ReceiveCounter => _receiveCounter;
}
