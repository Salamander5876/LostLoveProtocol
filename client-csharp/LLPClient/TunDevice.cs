using System.Runtime.InteropServices;
using Spectre.Console;

namespace LLPClient;

/// <summary>
/// TUN device для Windows через Wintun
/// </summary>
public class TunDevice : IDisposable
{
    private readonly VpnConfig _config;
    private IntPtr _adapter = IntPtr.Zero;
    private IntPtr _session = IntPtr.Zero;

    public TunDevice(VpnConfig config)
    {
        _config = config;
    }

    public async Task CreateAsync()
    {
        // TODO: Реализация создания TUN интерфейса через Wintun
        // Для MVP используем заглушку

        AnsiConsole.MarkupLine("[yellow]⚠ TUN device: Stub implementation[/]");
        AnsiConsole.MarkupLine($"[grey]  Interface: {_config.InterfaceName}[/]");
        AnsiConsole.MarkupLine($"[grey]  IP: {_config.IpAddress}[/]");
        AnsiConsole.MarkupLine($"[grey]  Mask: {_config.SubnetMask}[/]");
        AnsiConsole.MarkupLine($"[grey]  MTU: {_config.Mtu}[/]");

        await Task.CompletedTask;
    }

    public async Task<int> ReadAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        // TODO: Реализация чтения из TUN
        // Для MVP используем задержку
        await Task.Delay(100, cancellationToken);
        return 0; // Нет данных
    }

    public async Task WriteAsync(Memory<byte> data, CancellationToken cancellationToken)
    {
        // TODO: Реализация записи в TUN
        await Task.CompletedTask;
    }

    public void Dispose()
    {
        // TODO: Cleanup Wintun resources
        if (_session != IntPtr.Zero)
        {
            // WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            // WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }
    }
}

/// <summary>
/// Wintun DLL imports (будет реализовано позже)
/// </summary>
internal static class Wintun
{
    // TODO: Добавить P/Invoke для wintun.dll
    // https://www.wintun.net/

    /*
    [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunCreateAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
        ref Guid requestedGUID);

    [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunCloseAdapter(IntPtr adapter);

    // ... другие функции
    */
}
