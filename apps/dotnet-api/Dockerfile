FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY DotnetApi.csproj ./
RUN dotnet restore
COPY . ./
RUN dotnet publish DotnetApi.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
COPY --from=build /app/publish ./
# Non-root "app" user shipped in the image (UID in $APP_UID)
USER $APP_UID
ENTRYPOINT ["dotnet", "DotnetApi.dll"]
