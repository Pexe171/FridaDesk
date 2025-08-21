using System;
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

    public ScriptsViewModel()
    {
        Scripts.Add(new ScriptRef
        {
            Id = Guid.NewGuid(),
            Title = "Exemplo 1",
            Author = "Pexe (@David.devloli)",
            Source = ScriptSource.Internal
        });

        Scripts.Add(new ScriptRef
        {
            Id = Guid.NewGuid(),
            Title = "Exemplo 2",
            Author = "Pexe (@David.devloli)",
            Source = ScriptSource.Codeshare
        });
    }
}
