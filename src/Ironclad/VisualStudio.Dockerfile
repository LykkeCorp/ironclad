# NOTE (Cameron): Visual Studio tooling does not currently offer the flexibility to use the actual Dockerfile so this is included as a workaround.

FROM microsoft/dotnet:2.1-aspnetcore-runtime AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/dotnet:2.1-sdk AS build
WORKDIR /src
COPY . ./
WORKDIR /src/Ironclad
RUN dotnet publish -c Release -r linux-x64 -o /app

FROM base AS final
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "IroncladCustom.dll"]