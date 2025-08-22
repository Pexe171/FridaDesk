#!/bin/bash
# Autor: Pexe - Instagram: David.devloli
set -e
RID=linux-x64
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dotnet publish "$SCRIPT_DIR/../src/FridaHub.App/FridaHub.App.csproj" -c Release -r $RID -p:PublishSingleFile=true -p:SelfContained=true -o "$SCRIPT_DIR/publish/$RID"
