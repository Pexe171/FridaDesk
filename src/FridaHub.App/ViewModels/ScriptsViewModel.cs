using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Models;
using FridaHub.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.App.ViewModels;

public partial class ScriptsViewModel : ObservableObject
{
    private readonly IServiceScopeFactory _scopeFactory;
    private List<ScriptRef> allScripts = new();

    [ObservableProperty]
    private ObservableCollection<ScriptRef> scripts = new();

    [ObservableProperty]
    private ScriptRef? selectedScript;

    [ObservableProperty]
    private string searchText = string.Empty;

    public ScriptsViewModel(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
        _ = LoadAsync();
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    private async Task LoadAsync()
    {
        using var scope = _scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<IScriptsRepository>();
        var result = await repo.SearchAsync(string.Empty);
        if (result.IsSuccess && result.Value != null)
        {
            allScripts = result.Value.ToList();
            ApplyFilter();
        }
    }

    private void ApplyFilter()
    {
        var query = SearchText?.Trim() ?? string.Empty;
        IEnumerable<ScriptRef> filtered = string.IsNullOrWhiteSpace(query)
            ? allScripts
            : allScripts.Where(s =>
                s.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                s.Tags.Any(t => t.Contains(query, StringComparison.OrdinalIgnoreCase)));

        Scripts = new ObservableCollection<ScriptRef>(filtered);
    }
}
