using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using ImGuiNET;
using OpenTK.Graphics.OpenGL4;
using OpenTK.Mathematics;
using OpenTK.Windowing.Common;
using OpenTK.Windowing.Desktop;
using FridaHub.Core.Backends;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.ImGuiApp;

// Autor: Pexe (instagram David.devloli)
public class MainWindow : GameWindow
{
    private readonly IAdbBackend _adb;
    private readonly IFridaInstaller _installer;
    private readonly ImGuiController _imgui;
    private List<DeviceInfo> _devices = new();
    private readonly Dictionary<string, bool?> _installStatus = new();

    public MainWindow(IServiceProvider provider) : base(GameWindowSettings.Default, new NativeWindowSettings
    {
        ClientSize = new Vector2i(1280, 720),
        Title = "FridaDesk - Painel"
    })
    {
        _adb = provider.GetRequiredService<IAdbBackend>();
        _installer = provider.GetRequiredService<IFridaInstaller>();
        _imgui = new ImGuiController(Size.X, Size.Y);
    }

    protected override void OnRenderFrame(FrameEventArgs args)
    {
        base.OnRenderFrame(args);
        _imgui.Update(this, (float)args.Time);
        RenderUi();
        _imgui.Render();
        SwapBuffers();
    }

    private void RenderUi()
    {
        ImGui.Begin("FridaDesk - Painel");
        if (ImGui.BeginTabBar("main"))
        {
            if (ImGui.BeginTabItem("Devices"))
            {
                if (ImGui.Button("Detectar Devices"))
                {
                    var result = _adb.ListDevicesAsync().GetAwaiter().GetResult();
                    if (result.IsSuccess && result.Value != null)
                        _devices = result.Value.ToList();
                    else if (!result.IsSuccess)
                        LogService.Append($"! erro: {result.Error?.Message}");
                }

                foreach (var d in _devices)
                {
                    ImGui.Text($"{d.Serial} - {d.Model}");
                    ImGui.SameLine();
                    if (ImGui.Button($"Instalar##{d.Serial}"))
                    {
                        var res = _installer.InstallAsync(d.Serial).GetAwaiter().GetResult();
                        var ok = res.IsSuccess;
                        _installStatus[d.Serial] = ok;
                        LogService.Append(ok ? $"> frida-server pronto em {d.Serial}" : $"! erro em {d.Serial}: {res.Error?.Message}");
                    }
                    if (_installStatus.TryGetValue(d.Serial, out var st))
                    {
                        ImGui.SameLine();
                        if (st == true) ImGui.TextColored(new System.Numerics.Vector4(0, 1, 0, 1), "OK");
                        else if (st == false) ImGui.TextColored(new System.Numerics.Vector4(1, 0, 0, 1), "ERRO");
                    }
                }
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Scripts"))
            {
                ImGui.Text("TODO: lista scripts");
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Execuções"))
            {
                ImGui.Text("TODO: histórico");
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Configurações"))
            {
                ImGui.Text("TODO: configurações");
                ImGui.EndTabItem();
            }

            ImGui.EndTabBar();
        }

        ImGui.Separator();
        ImGui.Text("Console Logs:");
        ImGui.BeginChild("console", new System.Numerics.Vector2(0, 150), ImGuiChildFlags.None, ImGuiWindowFlags.HorizontalScrollbar);
        foreach (var line in LogService.Lines)
            ImGui.TextUnformatted(line);
        ImGui.EndChild();
        ImGui.End();
    }

    protected override void OnResize(ResizeEventArgs e)
    {
        base.OnResize(e);
        _imgui.WindowResized(e.Size.X, e.Size.Y);
        GL.Viewport(0, 0, e.Size.X, e.Size.Y);
    }

    protected override void OnUnload()
    {
        _imgui.Dispose();
        base.OnUnload();
    }
}
