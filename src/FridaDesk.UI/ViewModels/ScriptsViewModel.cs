// Autor: Pexe (Instagram: David.devloli)
using System.Collections.ObjectModel;

namespace FridaDesk.UI.ViewModels;

public class ScriptsViewModel
{
    public ObservableCollection<ScriptItem> Scripts { get; } = new()
    {
        new ScriptItem { Title="Dump UI", Author="User1", Source="Codeshare", Tags=new[]{"ui","android"} },
        new ScriptItem { Title="Bypass SSL", Author="User2", Source="Codeshare", Tags=new[]{"network","android"} },
        new ScriptItem { Title="Hook Touch", Author="User3", Source="Codeshare", Tags=new[]{"input","android"} },
        new ScriptItem { Title="Trace Calls", Author="User4", Source="Codeshare", Tags=new[]{"trace","ios"} },
        new ScriptItem { Title="List Classes", Author="User5", Source="Codeshare", Tags=new[]{"introspect","ios"} },
        new ScriptItem { Title="Interno A", Author="Equipe", Source="Interno", Tags=new[]{"interno","android"} },
        new ScriptItem { Title="Interno B", Author="Equipe", Source="Interno", Tags=new[]{"interno","ios"} },
        new ScriptItem { Title="Interno C", Author="Equipe", Source="Interno", Tags=new[]{"interno","android"} },
        new ScriptItem { Title="Interno D", Author="Equipe", Source="Interno", Tags=new[]{"interno","ios"} },
        new ScriptItem { Title="Interno E", Author="Equipe", Source="Interno", Tags=new[]{"interno","android"} }
    };
}

public class ScriptItem
{
    public string Title { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string[] Tags { get; set; } = System.Array.Empty<string>();
}
