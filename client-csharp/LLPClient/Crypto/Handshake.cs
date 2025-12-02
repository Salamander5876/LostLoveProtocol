using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace LLPClient.Crypto;

/// <summary>
/// Типы handshake сообщений
/// </summary>
public enum HandshakeMessageType : byte
{
    ClientHello = 1,
    ServerHello = 2,
    ClientVerify = 3,
    ServerVerify = 4
}

/// <summary>
/// Профили мимикрии трафика
/// </summary>
public enum MimicryProfile : ushort
{
    None = 0,
    VkVideo = 1,
    YandexMusic = 2,
    RuTube = 3
}

/// <summary>
/// CLIENT_HELLO сообщение
/// Формат: [msg_type:u8][public_key:32][random:32][profile_id:u16]
/// </summary>
public class ClientHello
{
    public const int X25519_KEY_SIZE = 32;
    public const int RANDOM_SIZE = 32;
    public const int MESSAGE_SIZE = 1 + X25519_KEY_SIZE + RANDOM_SIZE + 2; // 67 bytes

    public byte[] ClientPublicKey { get; set; } = new byte[X25519_KEY_SIZE];
    public byte[] ClientRandom { get; set; } = new byte[RANDOM_SIZE];
    public MimicryProfile MimicryProfile { get; set; }

    public ClientHello(byte[] clientPublicKey, MimicryProfile profile)
    {
        ClientPublicKey = clientPublicKey;
        RandomNumberGenerator.Fill(ClientRandom);
        MimicryProfile = profile;
    }

    public byte[] Serialize()
    {
        var buffer = new byte[MESSAGE_SIZE];
        var offset = 0;

        buffer[offset++] = (byte)HandshakeMessageType.ClientHello;
        Array.Copy(ClientPublicKey, 0, buffer, offset, X25519_KEY_SIZE);
        offset += X25519_KEY_SIZE;
        Array.Copy(ClientRandom, 0, buffer, offset, RANDOM_SIZE);
        offset += RANDOM_SIZE;

        // Big-endian u16
        var profileBytes = BitConverter.GetBytes((ushort)MimicryProfile);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(profileBytes);

        buffer[offset++] = profileBytes[0];
        buffer[offset++] = profileBytes[1];

        return buffer;
    }
}

public class ServerHello
{
    public const int MESSAGE_SIZE = 1 + 32 + 32 + 8; // 73 bytes

    public byte[] ServerPublicKey { get; set; } = new byte[32];
    public byte[] ServerRandom { get; set; } = new byte[32];
    public ulong SessionId { get; set; }

    public static ServerHello Deserialize(byte[] data)
    {
        if (data.Length < MESSAGE_SIZE)
            throw new InvalidDataException($"SERVER_HELLO too short: {data.Length} < {MESSAGE_SIZE}");

        var offset = 0;
        var msgType = data[offset++];
        if (msgType != (byte)HandshakeMessageType.ServerHello)
            throw new InvalidDataException($"Expected SERVER_HELLO (2), got {msgType}");

        var serverHello = new ServerHello();
        Array.Copy(data, offset, serverHello.ServerPublicKey, 0, 32);
        offset += 32;
        Array.Copy(data, offset, serverHello.ServerRandom, 0, 32);
        offset += 32;

        var sessionIdBytes = new byte[8];
        Array.Copy(data, offset, sessionIdBytes, 0, 8);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(sessionIdBytes);

        serverHello.SessionId = BitConverter.ToUInt64(sessionIdBytes, 0);
        return serverHello;
    }
}

public class ClientVerify
{
    public const int HMAC_TAG_SIZE = 32;
    public const int MESSAGE_SIZE = 1 + HMAC_TAG_SIZE; // 33 bytes

    public byte[] HmacTag { get; set; } = new byte[HMAC_TAG_SIZE];

    public ClientVerify(byte[] sessionKey, byte[] transcript)
    {
        using var hmac = new HMACSHA256(sessionKey);
        HmacTag = hmac.ComputeHash(transcript);
    }

    public byte[] Serialize()
    {
        var buffer = new byte[MESSAGE_SIZE];
        buffer[0] = (byte)HandshakeMessageType.ClientVerify;
        Array.Copy(HmacTag, 0, buffer, 1, HMAC_TAG_SIZE);
        return buffer;
    }
}

public class ServerVerify
{
    public const int HMAC_TAG_SIZE = 32;
    public const int MESSAGE_SIZE = 1 + HMAC_TAG_SIZE; // 33 bytes

    public byte[] HmacTag { get; set; } = new byte[HMAC_TAG_SIZE];

    public static ServerVerify Deserialize(byte[] data)
    {
        if (data.Length < MESSAGE_SIZE)
            throw new InvalidDataException($"SERVER_VERIFY too short: {data.Length} < {MESSAGE_SIZE}");

        var msgType = data[0];
        if (msgType != (byte)HandshakeMessageType.ServerVerify)
            throw new InvalidDataException($"Expected SERVER_VERIFY (4), got {msgType}");

        var serverVerify = new ServerVerify();
        Array.Copy(data, 1, serverVerify.HmacTag, 0, HMAC_TAG_SIZE);
        return serverVerify;
    }

    public bool Verify(byte[] sessionKey, byte[] transcript)
    {
        using var hmac = new HMACSHA256(sessionKey);
        var expectedTag = hmac.ComputeHash(transcript);
        return CryptographicOperations.FixedTimeEquals(expectedTag, HmacTag);
    }
}

/// <summary>
/// Клиентский handshake с X25519 через BouncyCastle
/// </summary>
public class ClientHandshake : IDisposable
{
    private const string HKDF_INFO = "llp-session-key-v1";

    private readonly X25519PrivateKeyParameters _privateKey;
    private readonly X25519PublicKeyParameters _publicKey;
    private readonly MimicryProfile _mimicryProfile;

    private ClientHello? _clientHello;
    private ServerHello? _serverHello;
    private byte[]? _sessionKey;

    public ulong? SessionId { get; private set; }
    public byte[]? SessionKey => _sessionKey;

    public ClientHandshake(MimicryProfile profile)
    {
        // Генерируем X25519 ключевую пару через BouncyCastle
        var secureRandom = new SecureRandom();
        var keyPairGenerator = new X25519KeyPairGenerator();
        keyPairGenerator.Init(new X25519KeyGenerationParameters(secureRandom));

        var keyPair = keyPairGenerator.GenerateKeyPair();
        _privateKey = (X25519PrivateKeyParameters)keyPair.Private;
        _publicKey = (X25519PublicKeyParameters)keyPair.Public;

        _mimicryProfile = profile;
    }

    public byte[] Start()
    {
        _clientHello = new ClientHello(_publicKey.GetEncoded(), _mimicryProfile);
        return _clientHello.Serialize();
    }

    public ulong ProcessServerHello(byte[] data)
    {
        if (_clientHello == null)
            throw new InvalidOperationException("Must call Start() first");

        _serverHello = ServerHello.Deserialize(data);
        SessionId = _serverHello.SessionId;

        // X25519 DH обмен ключами
        var serverPublicKey = new X25519PublicKeyParameters(_serverHello.ServerPublicKey, 0);
        var agreement = new X25519Agreement();
        agreement.Init(_privateKey);

        var sharedSecret = new byte[32];
        agreement.CalculateAgreement(serverPublicKey, sharedSecret, 0);

        // HKDF деривация
        var salt = new byte[64];
        Array.Copy(_clientHello.ClientRandom, 0, salt, 0, 32);
        Array.Copy(_serverHello.ServerRandom, 0, salt, 32, 32);

        _sessionKey = DeriveSessionKey(sharedSecret, salt, HKDF_INFO);

        // Зануляем shared secret
        CryptographicOperations.ZeroMemory(sharedSecret);

        return _serverHello.SessionId;
    }

    public byte[] SendClientVerify()
    {
        if (_sessionKey == null)
            throw new InvalidOperationException("Must call ProcessServerHello() first");

        var transcript = BuildTranscript();
        var clientVerify = new ClientVerify(_sessionKey, transcript);
        return clientVerify.Serialize();
    }

    public void ProcessServerVerify(byte[] data)
    {
        if (_sessionKey == null)
            throw new InvalidOperationException("Handshake not initialized");

        var serverVerify = ServerVerify.Deserialize(data);
        var transcript = BuildTranscript();

        if (!serverVerify.Verify(_sessionKey, transcript))
            throw new CryptographicException("SERVER_VERIFY HMAC verification failed");
    }

    private byte[] BuildTranscript()
    {
        if (_clientHello == null || _serverHello == null)
            throw new InvalidOperationException("Handshake messages not initialized");

        var clientHelloBytes = _clientHello.Serialize();
        var transcript = new byte[ClientHello.MESSAGE_SIZE + ServerHello.MESSAGE_SIZE];
        Array.Copy(clientHelloBytes, 0, transcript, 0, ClientHello.MESSAGE_SIZE);

        var offset = ClientHello.MESSAGE_SIZE;
        transcript[offset++] = (byte)HandshakeMessageType.ServerHello;
        Array.Copy(_serverHello.ServerPublicKey, 0, transcript, offset, 32);
        offset += 32;
        Array.Copy(_serverHello.ServerRandom, 0, transcript, offset, 32);
        offset += 32;

        var sessionIdBytes = BitConverter.GetBytes(_serverHello.SessionId);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(sessionIdBytes);
        Array.Copy(sessionIdBytes, 0, transcript, offset, 8);

        return transcript;
    }

    private static byte[] DeriveSessionKey(byte[] sharedSecret, byte[] salt, string info)
    {
        var sessionKey = new byte[32];
        var infoBytes = System.Text.Encoding.UTF8.GetBytes(info);

        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            sharedSecret,
            sessionKey,
            salt,
            infoBytes);

        return sessionKey;
    }

    public void Dispose()
    {
        if (_sessionKey != null)
            CryptographicOperations.ZeroMemory(_sessionKey);
    }
}
