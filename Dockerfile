FROM golang:1.22-alpine AS build

ARG APP_NAME

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

COPY ./vendor ./vendor
COPY ./protogen ./protogen
COPY ./internal ./internal
COPY ./cmd/${APP_NAME} ./cmd/${APP_NAME}

RUN go build -o /${APP_NAME} github.com/ramonberrutti/diy-service-mesh/cmd/${APP_NAME}

FROM alpine

ARG APP_NAME
ENV APP_NAME_ENV=/$APP_NAME

WORKDIR /

COPY --from=build /${APP_NAME} /${APP_NAME}

EXPOSE 9090

# ENTRYPOINT 
ENTRYPOINT ${APP_NAME_ENV}
