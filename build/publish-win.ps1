param(
    [string]$RID = "win-x64"
)
# Autor: Pexe - Instagram: David.devloli
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$OutputDir = Join-Path $ScriptDir "publish/$RID"
dotnet publish "$ScriptDir/../src/FridaHub.App/FridaHub.App.csproj" -c Release -r $RID -p:PublishSingleFile=true -p:SelfContained=false -o $OutputDir
