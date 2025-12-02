using Tomlyn;
using System.Net;

namespace LLPClient;

public class ClientConfig
{
    public ServerConfig Server { get; set; } = new();
    public VpnConfig Vpn { get; set; } = new();
    public SecurityConfig Security { get; set; } = new();
    public ReconnectConfig Reconnect { get; set; } = new();
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

public class ServerConfig
{
    public string Address { get; set; } = "";
}

public class VpnConfig
{
    public string InterfaceName { get; set; } = "llp0";
    public string IpAddress { get; set; } = "";
    public string SubnetMask { get; set; } = "255.255.255.0";
    public int Mtu { get; set; } = 1420;
}

public class SecurityConfig
{
    public string MimicryProfile { get; set; } = "vk_video";
    public bool EnableReplayProtection { get; set; } = true;
    public int MaxPacketAgeSec { get; set; } = 60;
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
}
