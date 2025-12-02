using Spectre.Console;
using System.Net;
using System.Net.Sockets;

namespace LLPClient;

class Program
{
    static async Task<int> Main(string[] args)
    {
        try
        {
            // Проверка прав администратора
            if (!IsAdministrator())
            {
                AnsiConsole.MarkupLine("[red]✗[/] Требуются права администратора!");
                AnsiConsole.MarkupLine("[yellow]ℹ[/] Запустите программу от имени администратора");
                Console.ReadKey();
                return 1;
            }

            ShowBanner();

            // Парсинг аргументов
            if (args.Length > 0 && args[0] == "--config" && args.Length > 1)
            {
                var configPath = args[1];
                return await RunClient(configPath);
            }

            // Интерактивное меню
            return await ShowMainMenu();
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Критическая ошибка:[/] {ex.Message}");
            AnsiConsole.WriteException(ex);
            return 1;
        }
    }

    static void ShowBanner()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(
            new FigletText("LLP Client")
                .Centered()
                .Color(Color.Purple));

        AnsiConsole.MarkupLine("[grey]LostLoveProtocol VPN Client v1.0.0[/]");
        AnsiConsole.MarkupLine("[grey]Windows .NET Implementation[/]");
        AnsiConsole.WriteLine();
    }

    static async Task<int> ShowMainMenu()
    {
        var configsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "configs");
        Directory.CreateDirectory(configsDir);

        while (true)
        {
            ShowBanner();

            var configs = Directory.GetFiles(configsDir, "*.toml")
                .Select(Path.GetFileNameWithoutExtension)
                .ToArray();

            if (configs.Length == 0)
            {
                var panel = new Panel($"[yellow]Нет доступных конфигураций[/]\n\n" +
                    $"Поместите файлы .toml в папку:\n[blue]{configsDir}[/]")
                    .Border(BoxBorder.Rounded)
                    .BorderColor(Color.Yellow);
                AnsiConsole.Write(panel);

                Console.WriteLine("\nНажмите любую клавишу для обновления или Q для выхода...");
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Q) return 0;
                continue;
            }

            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Blue)
                .AddColumn(new TableColumn("[yellow]#[/]").Centered())
                .AddColumn(new TableColumn("[yellow]Конфигурация[/]"))
                .AddColumn(new TableColumn("[yellow]Размер[/]").RightAligned());

            for (int i = 0; i < configs.Length; i++)
            {
                var filePath = Path.Combine(configsDir, configs[i] + ".toml");
                var fileInfo = new FileInfo(filePath);
                var sizeKb = fileInfo.Length / 1024.0;

                table.AddRow(
                    $"[cyan]{i + 1}[/]",
                    configs[i]!,
                    $"[grey]{sizeKb:F2} KB[/]"
                );
            }

            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[grey][[R]] Обновить  [[Q]] Выход[/]");
            AnsiConsole.WriteLine();

            var choice = AnsiConsole.Ask<string>("Выберите конфигурацию:");

            if (choice.Equals("Q", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (choice.Equals("R", StringComparison.OrdinalIgnoreCase))
                continue;

            if (int.TryParse(choice, out int num) && num > 0 && num <= configs.Length)
            {
                var configPath = Path.Combine(configsDir, configs[num - 1] + ".toml");
                await RunClient(configPath);
            }
            else
            {
                AnsiConsole.MarkupLine("[red]✗ Неверный выбор[/]");
                await Task.Delay(1000);
            }
        }
    }

    static async Task<int> RunClient(string configPath)
    {
        try
        {
            ShowBanner();

            var config = await ClientConfig.LoadAsync(configPath);

            var panel = new Panel($"[green]Подключение к VPN[/]\n\n" +
                $"Сервер: [cyan]{config.Server.Address}[/]\n" +
                $"VPN IP: [cyan]{config.Vpn.IpAddress}[/]\n" +
                $"Профиль: [cyan]{config.Security.MimicryProfile}[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Green);

            AnsiConsole.Write(panel);
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]⚠ Нажмите Ctrl+C для отключения[/]");
            AnsiConsole.WriteLine();

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
            };

            var client = new VpnClient(config);

            await AnsiConsole.Status()
                .Spinner(Spinner.Known.Dots)
                .SpinnerStyle(Style.Parse("green"))
                .StartAsync("Подключение...", async ctx =>
                {
                    await client.ConnectAsync(cts.Token);
                });

            AnsiConsole.MarkupLine("[green]✓ Подключено![/]");
            AnsiConsole.WriteLine();

            await client.RunAsync(cts.Token);

            return 0;
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]ℹ Отключение...[/]");
            return 0;
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Ошибка:[/] {ex.Message}");
            Console.ReadKey();
            return 1;
        }
    }

    static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
