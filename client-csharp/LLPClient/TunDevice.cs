using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
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
    private bool _isRunning = false;

    public TunDevice(VpnConfig config)
    {
        _config = config;
    }

    public async Task CreateAsync()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Wintun only works on Windows");

        try
        {
            // Генерируем GUID для адаптера
            var guid = Guid.NewGuid();

            // Создаём Wintun адаптер
            _adapter = Wintun.WintunCreateAdapter(
                _config.InterfaceName,
                "LostLoveProtocol",
                ref guid);

            if (_adapter == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw new Exception($"Failed to create Wintun adapter. Error code: {error}");
            }

            AnsiConsole.MarkupLine($"[green]✓[/] Wintun adapter created: {_config.InterfaceName}");

            // Устанавливаем IP адрес через netsh
            await SetIpAddressAsync();

            // Создаём сессию
            _session = Wintun.WintunStartSession(_adapter, 0x400000); // 4MB ring buffer
            if (_session == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                throw new Exception($"Failed to start Wintun session. Error code: {error}");
            }

            _isRunning = true;
            AnsiConsole.MarkupLine($"[green]✓[/] Wintun session started");
            AnsiConsole.MarkupLine($"[grey]  Interface: {_config.InterfaceName}[/]");
            AnsiConsole.MarkupLine($"[grey]  IP: {_config.IpAddress}[/]");
            AnsiConsole.MarkupLine($"[grey]  Mask: {_config.SubnetMask}[/]");
            AnsiConsole.MarkupLine($"[grey]  MTU: {_config.Mtu}[/]");

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]⚠ Wintun initialization failed: {ex.Message}[/]");
            AnsiConsole.MarkupLine($"[yellow]  Falling back to stub implementation[/]");
            _isRunning = false;
        }
    }

    private async Task SetIpAddressAsync()
    {
        try
        {
            // Используем netsh для настройки IP
            var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"interface ip set address name=\"{_config.InterfaceName}\" static {_config.IpAddress} {_config.SubnetMask}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });

            if (process != null)
            {
                await process.WaitForExitAsync();
                if (process.ExitCode == 0)
                {
                    AnsiConsole.MarkupLine($"[green]✓[/] IP address configured: {_config.IpAddress}");
                }
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[yellow]⚠ Failed to set IP address: {ex.Message}[/]");
        }
    }

    public async Task<int> ReadAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        if (!_isRunning || _session == IntPtr.Zero)
        {
            await Task.Delay(100, cancellationToken);
            return 0;
        }

        try
        {
            // Неблокирующее чтение из Wintun
            var packetPtr = Wintun.WintunReceivePacket(_session, out var packetSize);
            if (packetPtr == IntPtr.Zero)
            {
                // Нет пакетов, ждём
                await Task.Delay(1, cancellationToken);
                return 0;
            }

            try
            {
                // Копируем данные
                var size = Math.Min((int)packetSize, buffer.Length);
                Marshal.Copy(packetPtr, buffer, 0, size);
                return size;
            }
            finally
            {
                // Освобождаем пакет
                Wintun.WintunReleaseReceivePacket(_session, packetPtr);
            }
        }
        catch (Exception)
        {
            await Task.Delay(10, cancellationToken);
            return 0;
        }
    }

    public async Task WriteAsync(Memory<byte> data, CancellationToken cancellationToken)
    {
        if (!_isRunning || _session == IntPtr.Zero)
        {
            await Task.CompletedTask;
            return;
        }

        try
        {
            // Аллоцируем пакет в Wintun
            var packetPtr = Wintun.WintunAllocateSendPacket(_session, (uint)data.Length);
            if (packetPtr == IntPtr.Zero)
            {
                return; // Ring buffer full
            }

            // Копируем данные
            Marshal.Copy(data.ToArray(), 0, packetPtr, data.Length);

            // Отправляем пакет
            Wintun.WintunSendPacket(_session, packetPtr);

            await Task.CompletedTask;
        }
        catch (Exception)
        {
            // Игнорируем ошибки записи
        }
    }

    public void Dispose()
    {
        _isRunning = false;

        if (_session != IntPtr.Zero)
        {
            Wintun.WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            Wintun.WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }
    }
}

/// <summary>
/// Wintun DLL P/Invoke definitions
/// https://www.wintun.net/
/// </summary>
internal static class Wintun
{
    private const string DllName = "wintun.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunCreateAdapter(
        [MarshalAs(UnmanagedType.LPWStr)] string name,
        [MarshalAs(UnmanagedType.LPWStr)] string tunnelType,
        ref Guid requestedGUID);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunEndSession(IntPtr session);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    public static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

    [DllImport(DllName, CallingConvention = CallingConvention.StdCall)]
    public static extern void WintunSendPacket(IntPtr session, IntPtr packet);
}
