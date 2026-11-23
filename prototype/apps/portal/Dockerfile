# Phase 6: access approval portal. One container: the ASP.NET Core API serves the Angular UI
# from wwwroot (same origin, no CORS).
FROM node:24-alpine AS ui
WORKDIR /ui
ENV NG_CLI_ANALYTICS=false
COPY ui/package.json ./
RUN npm install --no-audit --no-fund
COPY ui/ ./
RUN npx ng build --configuration production

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Portal.csproj ./
RUN dotnet restore
COPY *.cs appsettings.json ./
RUN dotnet publish Portal.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
COPY --from=build /app/publish ./
COPY --from=ui /ui/dist/portal-ui/browser ./wwwroot
# Non-root "app" user shipped in the image (UID 1654 in $APP_UID)
USER $APP_UID
ENTRYPOINT ["dotnet", "Portal.dll"]
