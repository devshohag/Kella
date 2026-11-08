# Builds Kella.Api or Kella.Worker: docker build --build-arg PROJECT=Kella.Api .
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG PROJECT=Kella.Api
WORKDIR /src
COPY . .
RUN dotnet publish src/${PROJECT}/${PROJECT}.csproj -c Release -o /out /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
ARG PROJECT=Kella.Api
ENV APP_DLL=${PROJECT}.dll
WORKDIR /app
COPY --from=build /out .
USER app
ENTRYPOINT ["sh", "-c", "exec dotnet $APP_DLL"]
