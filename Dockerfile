FROM golang:1.10 AS builder
ARG APP=github.com/Oxalide/kibana-sync
WORKDIR $GOPATH/src/$APP
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /app .

FROM alpine:3.7
RUN apk add --no-cache --update dumb-init ca-certificates
COPY --from=builder /app /app
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/app"]
