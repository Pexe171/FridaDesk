using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.App.ViewModels;

public partial class HistoryViewModel : ObservableObject
{
    private readonly IServiceScopeFactory _scopeFactory;
    private List<RunRecord> allRecords = new();

    public HistoryViewModel(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
        _ = LoadAsync();
    }

    [ObservableProperty]
    private ObservableCollection<RunRecord> records = new();

    [ObservableProperty]
    private RunRecord? selectedRecord;

    [ObservableProperty]
    private DateTime? startDate;

    [ObservableProperty]
    private DateTime? endDate;

    [ObservableProperty]
    private RunStatus? selectedStatus;

    [ObservableProperty]
    private string scriptFilter = string.Empty;

    [ObservableProperty]
    private string deviceFilter = string.Empty;

    public IEnumerable<RunStatus> Statuses { get; } = Enum.GetValues<RunStatus>();

    partial void OnStartDateChanged(DateTime? value) => ApplyFilter();
    partial void OnEndDateChanged(DateTime? value) => ApplyFilter();
    partial void OnSelectedStatusChanged(RunStatus? value) => ApplyFilter();
    partial void OnScriptFilterChanged(string value) => ApplyFilter();
    partial void OnDeviceFilterChanged(string value) => ApplyFilter();

    private async Task LoadAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<IRunsRepository>();
        var result = await repo.SearchAsync(string.Empty);
        if (result.IsSuccess && result.Value is { } list)
        {
            allRecords = list.ToList();
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        IEnumerable<RunRecord> query = allRecords;

        if (StartDate is { } sd)
            query = query.Where(r => r.StartedAtUtc?.Date >= sd.Date);

        if (EndDate is { } ed)
            query = query.Where(r => r.StartedAtUtc?.Date <= ed.Date);

        if (SelectedStatus is { } st)
            query = query.Where(r => r.Status == st);

        if (!string.IsNullOrWhiteSpace(ScriptFilter))
            query = query.Where(r => r.ScriptId.ToString().Contains(ScriptFilter, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(DeviceFilter))
            query = query.Where(r => r.DeviceSerial.Contains(DeviceFilter, StringComparison.OrdinalIgnoreCase));

        Records = new ObservableCollection<RunRecord>(query);
    }

    [RelayCommand]
    private void OpenLog(RunRecord record)
    {
        if (string.IsNullOrWhiteSpace(record.LogPath) || !File.Exists(record.LogPath))
            return;
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = record.LogPath,
                UseShellExecute = true
            });
        }
        catch
        {
            // ignorar
        }
    }
}

