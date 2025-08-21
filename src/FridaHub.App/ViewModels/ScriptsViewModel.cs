using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using FridaHub.Core.Models;

namespace FridaHub.App.ViewModels;

public partial class ScriptsViewModel : ObservableObject
{
    [ObservableProperty]
    private ObservableCollection<ScriptRef> scripts = new();

    [ObservableProperty]
    private ScriptRef? selectedScript;
}
