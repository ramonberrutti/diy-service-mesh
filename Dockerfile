FROM golang:1.22-alpine AS build

ARG APP_NAME

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

COPY ./vendor ./vendor
COPY ./protogen ./protogen
COPY ./cmd/${APP_NAME} ./cmd/${APP_NAME}

RUN go build -o /${APP_NAME} github.com/ramonberrutti/diy-service-mesh/cmd/${APP_NAME}

FROM alpine

ARG APP_NAME
ARG SET_CAP
ENV APP_NAME_ENV=/$APP_NAME

WORKDIR /

COPY --from=build /${APP_NAME} /${APP_NAME}

RUN if [ "$SET_CAP" = "true" ]; then apk add --no-cache iptables libcap && setcap cap_net_raw,cap_net_admin=+eip /$APP_NAME; fi

# ENTRYPOINT 
ENTRYPOINT ${APP_NAME_ENV}
