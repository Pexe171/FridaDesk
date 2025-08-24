// Autor: Pexe (Instagram: David.devloli)
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Interactivity;
using FridaDesk.UI;
using Avalonia;
using FridaDesk.UI.ViewModels;
using FridaDesk.UI.Controls;
using FridaDesk.Processes;
using FridaDesk.Core.Models;
using FridaDesk.Core.Interfaces;
using FridaDesk.Core.Results;

namespace FridaDesk.UI.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContext = new SettingsViewModel();
    }

    private void InitializeComponent()
    {
        AvaloniaXamlLoader.Load(this);
    }

    private async void OnTestTools(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not SettingsViewModel vm)
            return;

        var settings = new Settings
        {
            AdbPath = vm.AdbPath,
            FridaPath = vm.FridaPath,
            ResourcesFolder = string.Empty
        };

        var svc = new MemorySettingsService(settings);
        var runner = new ProcessRunner(svc);

        if (TopLevel.GetTopLevel(this) is MainWindow mw)
        {
            var console = mw.FindControl<ConsolePanel>("Console");
            if (console != null)
            {
                await RunAndLogAsync(console, runner, "adb", "version");
                await RunAndLogAsync(console, runner, "frida", "--version");
            }
        }
    }

    private static async Task RunAndLogAsync(ConsolePanel console, ProcessRunner runner, string file, string args)
    {
        try
        {
            var run = runner.Run(file, args);
            await foreach (var line in run.Output)
                console.Text += line.Line + "\n";
            await run.WaitForExitAsync();
        }
        catch (Exception ex)
        {
            console.Text += ex.Message + "\n";
        }
    }

    private class MemorySettingsService : ISettingsService
    {
        public Settings? Current { get; private set; }
        public MemorySettingsService(Settings settings) => Current = settings;
        public Task<Result<Settings>> LoadAsync() => Task.FromResult(Result<Settings>.Success(Current ?? new Settings()));
        public Task<Result> SaveAsync(Settings settings)
        {
            Current = settings;
            return Task.FromResult(Result.Success());
        }
    }
}
