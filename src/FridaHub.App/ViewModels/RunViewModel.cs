using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class RunViewModel : ObservableObject
{
    private readonly ISettingsService _settingsService;

    public RunViewModel(ISettingsService settingsService)
    {
        _settingsService = settingsService;

        var result = _settingsService.LoadAsync().GetAwaiter().GetResult();
        if (result.IsSuccess && result.Value is { } settings)
        {
            IsAuthorized = settings.AuthorizedUseAccepted;
        }
    }

    [ObservableProperty]
    private ObservableCollection<ProcessLine> output = new();

    [ObservableProperty]
    private bool isAuthorized;

    public async Task SaveAuthorizationAsync()
    {
        var settings = _settingsService.Current ?? new Settings();
        settings.AuthorizedUseAccepted = IsAuthorized;
        await _settingsService.SaveAsync(settings);
    }
}
