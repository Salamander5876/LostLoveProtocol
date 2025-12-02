using Spectre.Console;
using System.Net;
using System.Net.Sockets;
using LLPClient.Crypto;

namespace LLPClient;

public class VpnClient
{
    private readonly ClientConfig _config;
    private TcpClient? _tcpClient;
    private NetworkStream? _stream;
    private TunDevice? _tunDevice;
    private byte[]? _sessionKey;
    private ulong? _sessionId;

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

        // Определяем профиль мимикрии из конфигурации
        var profile = _config.Security.MimicryProfile.ToLower() switch
        {
            "vk_video" => MimicryProfile.VkVideo,
            "yandex_music" => MimicryProfile.YandexMusic,
            "rutube" => MimicryProfile.RuTube,
            "none" => MimicryProfile.None,
            _ => MimicryProfile.VkVideo
        };

        var handshake = new ClientHandshake(profile);

        // Шаг 1: Отправляем CLIENT_HELLO с length-prefix (u32 big-endian)
        AnsiConsole.MarkupLine("[grey]  → Отправка CLIENT_HELLO...[/]");
        var clientHelloBytes = handshake.Start();

        // Отправляем длину (u32 big-endian), затем само сообщение
        var lengthBytes = BitConverter.GetBytes((uint)clientHelloBytes.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        await _stream.WriteAsync(lengthBytes, cancellationToken);
        await _stream.WriteAsync(clientHelloBytes, cancellationToken);

        // Шаг 2: Получаем SERVER_HELLO (с length-prefix)
        AnsiConsole.MarkupLine("[grey]  → Ожидание SERVER_HELLO...[/]");

        // Читаем длину (u32 big-endian)
        var lengthBuf = new byte[4];
        await ReadExactAsync(_stream, lengthBuf, cancellationToken);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBuf);
        var messageLength = BitConverter.ToUInt32(lengthBuf, 0);

        if (messageLength != ServerHello.MESSAGE_SIZE)
            throw new Exception($"Unexpected SERVER_HELLO length: {messageLength} != {ServerHello.MESSAGE_SIZE}");

        // Читаем само сообщение
        var serverHelloBuffer = new byte[ServerHello.MESSAGE_SIZE];
        var bytesRead = await ReadExactAsync(_stream, serverHelloBuffer, cancellationToken);

        if (bytesRead < ServerHello.MESSAGE_SIZE)
            throw new Exception($"Incomplete SERVER_HELLO: {bytesRead} < {ServerHello.MESSAGE_SIZE}");

        _sessionId = handshake.ProcessServerHello(serverHelloBuffer);
        AnsiConsole.MarkupLine($"[grey]  ✓ Session ID: {_sessionId:X16}[/]");

        // Шаг 3: Отправляем CLIENT_VERIFY (с length-prefix)
        AnsiConsole.MarkupLine("[grey]  → Отправка CLIENT_VERIFY...[/]");
        var clientVerifyBytes = handshake.SendClientVerify();

        lengthBytes = BitConverter.GetBytes((uint)clientVerifyBytes.Length);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBytes);

        await _stream.WriteAsync(lengthBytes, cancellationToken);
        await _stream.WriteAsync(clientVerifyBytes, cancellationToken);

        // Шаг 4: Получаем SERVER_VERIFY (с length-prefix)
        AnsiConsole.MarkupLine("[grey]  → Ожидание SERVER_VERIFY...[/]");

        // Читаем длину
        lengthBuf = new byte[4];
        await ReadExactAsync(_stream, lengthBuf, cancellationToken);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(lengthBuf);
        messageLength = BitConverter.ToUInt32(lengthBuf, 0);

        if (messageLength != ServerVerify.MESSAGE_SIZE)
            throw new Exception($"Unexpected SERVER_VERIFY length: {messageLength} != {ServerVerify.MESSAGE_SIZE}");

        // Читаем сообщение
        var serverVerifyBuffer = new byte[ServerVerify.MESSAGE_SIZE];
        bytesRead = await ReadExactAsync(_stream, serverVerifyBuffer, cancellationToken);

        if (bytesRead < ServerVerify.MESSAGE_SIZE)
            throw new Exception($"Incomplete SERVER_VERIFY: {bytesRead} < {ServerVerify.MESSAGE_SIZE}");

        handshake.ProcessServerVerify(serverVerifyBuffer);

        // Сохраняем сессионный ключ
        _sessionKey = handshake.SessionKey;

        AnsiConsole.MarkupLine("[green]  ✓ Handshake успешно завершён![/]");
    }

    /// <summary>
    /// Читает точное количество байтов из потока
    /// </summary>
    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var bytesRead = await stream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead),
                cancellationToken);

            if (bytesRead == 0)
                return totalRead; // Соединение закрыто

            totalRead += bytesRead;
        }
        return totalRead;
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
