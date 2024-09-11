ENV GO_ENV "PROD"
ENV SECRET "32-byte sequence. Keep it secret"
ENV DATABASE_URL ""
EXPOSE 8080
WORKDIR ../build
RUN go build -o auth_service -modfile ../go.mod -mod vendor ../cmd/main.go
COPY ../config.json .
CMD ["./auth_service"]