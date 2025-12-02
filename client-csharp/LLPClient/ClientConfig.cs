using Tomlyn;
using System.Net;
using Tomlyn.Model;

namespace LLPClient;

public class ClientConfig
{
    public NetworkConfig? Network { get; set; }
    public ServerConfig Server { get; set; } = new();
    public VpnConfig Vpn { get; set; } = new();
    public SecurityConfig Security { get; set; } = new();
    public ReconnectConfig? Reconnect { get; set; }
    public LoggingConfig Logging { get; set; } = new();

    public static async Task<ClientConfig> LoadAsync(string path)
    {
        var toml = await File.ReadAllTextAsync(path);
        var config = Toml.ToModel<ClientConfig>(toml);

        // Валидация
        if (string.IsNullOrEmpty(config.Server.Address))
            throw new Exception("Server address not configured");

        if (string.IsNullOrEmpty(config.Vpn.IpAddress))
            throw new Exception("VPN IP address not configured");

        return config;
    }
}

public class NetworkConfig
{
    public string BindIp { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 8443;
    public int MaxConnections { get; set; } = 1000;
    public int ConnectionTimeoutSecs { get; set; } = 30;
}

public class ServerConfig
{
    public string Address { get; set; } = "";
}

public class VpnConfig
{
    public string InterfaceName { get; set; } = "llp0";
    public string IpAddress { get; set; } = "";
    public string SubnetMask { get; set; } = "255.255.255.0";
    public string? Subnet { get; set; }
    public string? ServerIp { get; set; }
    public List<string>? DnsServers { get; set; }
    public int Mtu { get; set; } = 1420;
}

public class SecurityConfig
{
    public string MimicryProfile { get; set; } = "vk_video";
    public string? DefaultMimicryProfile { get; set; }
    public bool EnableReplayProtection { get; set; } = true;
    public int MaxPacketAgeSec { get; set; } = 60;
    public long? SessionLifetimeSecs { get; set; }
    public long? KeepaliveIntervalSecs { get; set; }
    public long? KeepaliveTimeoutSecs { get; set; }
    public long? MaxTimestampDriftSecs { get; set; }
}

public class ReconnectConfig
{
    public bool Enable { get; set; } = true;
    public int InitialDelayMs { get; set; } = 1000;
    public int MaxDelayMs { get; set; } = 30000;
    public int MaxAttempts { get; set; } = 0; // 0 = infinite
}

public class LoggingConfig
{
    public string Level { get; set; } = "info";
    public bool? LogToFile { get; set; }
    public string? LogFilePath { get; set; }
}
