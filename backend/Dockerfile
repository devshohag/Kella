# Builds Shield.Api or Shield.Worker: docker build --build-arg PROJECT=Shield.Api .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG PROJECT=Shield.Api
WORKDIR /src
COPY . .
RUN dotnet publish src/${PROJECT}/${PROJECT}.csproj -c Release -o /out /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
ARG PROJECT=Shield.Api
ENV APP_DLL=${PROJECT}.dll
WORKDIR /app
COPY --from=build /out .
USER app
ENTRYPOINT ["sh", "-c", "exec dotnet $APP_DLL"]
