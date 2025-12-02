using Spectre.Console;
using System.Net;
using System.Net.Sockets;

namespace LLPClient;

public class VpnClient
{
    private readonly ClientConfig _config;
    private TcpClient? _tcpClient;
    private NetworkStream? _stream;
    private TunDevice? _tunDevice;

    public VpnClient(ClientConfig config)
    {
        _config = config;
    }

    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        // Парсинг адреса сервера
        var parts = _config.Server.Address.Split(':');
        if (parts.Length != 2)
            throw new Exception($"Invalid server address format: {_config.Server.Address}");

        var host = parts[0];
        var port = int.Parse(parts[1]);

        AnsiConsole.MarkupLine($"[grey]→ Подключение к {host}:{port}...[/]");

        // TCP подключение
        _tcpClient = new TcpClient();
        await _tcpClient.ConnectAsync(host, port, cancellationToken);
        _stream = _tcpClient.GetStream();

        AnsiConsole.MarkupLine("[green]✓[/] TCP подключение установлено");

        // Создание TUN интерфейса
        AnsiConsole.MarkupLine($"[grey]→ Создание TUN интерфейса {_config.Vpn.InterfaceName}...[/]");
        _tunDevice = new TunDevice(_config.Vpn);
        await _tunDevice.CreateAsync();

        AnsiConsole.MarkupLine($"[green]✓[/] TUN интерфейс создан: {_config.Vpn.IpAddress}");

        // Handshake
        AnsiConsole.MarkupLine("[grey]→ Выполнение handshake...[/]");
        await PerformHandshakeAsync(cancellationToken);

        AnsiConsole.MarkupLine("[green]✓[/] Handshake завершён");
    }

    private async Task PerformHandshakeAsync(CancellationToken cancellationToken)
    {
        if (_stream == null)
            throw new InvalidOperationException("Not connected");

        // TODO: Реализовать полный handshake протокол
        // Пока заглушка - просто отправляем hello
        var hello = System.Text.Encoding.UTF8.GetBytes("HELLO_LLP");
        await _stream.WriteAsync(hello, cancellationToken);

        // Ждём ответ
        var buffer = new byte[1024];
        var bytesRead = await _stream.ReadAsync(buffer, cancellationToken);

        if (bytesRead == 0)
            throw new Exception("Server closed connection during handshake");
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (_stream == null || _tunDevice == null)
            throw new InvalidOperationException("Not connected");

        var table = new Table()
            .Border(TableBorder.None)
            .AddColumn(new TableColumn("Метрика"))
            .AddColumn(new TableColumn("Значение"))
            .HideHeaders();

        await AnsiConsole.Live(table)
            .AutoClear(false)
            .StartAsync(async ctx =>
            {
                long bytesSent = 0;
                long bytesReceived = 0;
                int packetsSent = 0;
                int packetsReceived = 0;
                var startTime = DateTime.Now;

                // Задача чтения из TUN и отправки на сервер
                var tunToServerTask = Task.Run(async () =>
                {
                    var buffer = new byte[_config.Vpn.Mtu + 100];

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            var bytesRead = await _tunDevice.ReadAsync(buffer, cancellationToken);
                            if (bytesRead > 0)
                            {
                                // TODO: Шифрование и упаковка в мимикрию
                                await _stream!.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);

                                bytesSent += bytesRead;
                                packetsSent++;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine($"[red]✗ TUN→Server error: {ex.Message}[/]");
                        }
                    }
                }, cancellationToken);

                // Задача чтения с сервера и записи в TUN
                var serverToTunTask = Task.Run(async () =>
                {
                    var buffer = new byte[_config.Vpn.Mtu + 100];

                    while (!cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            var bytesRead = await _stream!.ReadAsync(buffer, cancellationToken);
                            if (bytesRead > 0)
                            {
                                // TODO: Расшифровка и распаковка мимикрии
                                await _tunDevice.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);

                                bytesReceived += bytesRead;
                                packetsReceived++;
                            }
                            else
                            {
                                throw new Exception("Server closed connection");
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (Exception ex)
                        {
                            AnsiConsole.MarkupLine($"[red]✗ Server→TUN error: {ex.Message}[/]");
                            break;
                        }
                    }
                }, cancellationToken);

                // Задача обновления статистики
                var statsTask = Task.Run(async () =>
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        var uptime = DateTime.Now - startTime;

                        table.Rows.Clear();
                        table.AddRow("[green]↑ Отправлено[/]", $"[cyan]{FormatBytes(bytesSent)}[/] ({packetsSent} пакетов)");
                        table.AddRow("[blue]↓ Получено[/]", $"[cyan]{FormatBytes(bytesReceived)}[/] ({packetsReceived} пакетов)");
                        table.AddRow("[yellow]⏱ Время работы[/]", $"[cyan]{uptime:hh\\:mm\\:ss}[/]");
                        table.AddRow("[grey]📡 Сервер[/]", $"[grey]{_config.Server.Address}[/]");

                        ctx.Refresh();

                        await Task.Delay(1000, cancellationToken);
                    }
                }, cancellationToken);

                await Task.WhenAny(tunToServerTask, serverToTunTask, statsTask);
            });
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = { "B", "KB", "MB", "GB" };
        double len = bytes;
        int order = 0;

        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return $"{len:0.##} {sizes[order]}";
    }

    public void Dispose()
    {
        _stream?.Dispose();
        _tcpClient?.Dispose();
        _tunDevice?.Dispose();
    }
}
