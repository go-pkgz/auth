FROM umputun/baseimage:buildgo-latest as build-backend

COPY backend /src/backend
WORKDIR /src/backend
RUN go get && go get -u github.com/go-pkgz/auth
RUN go build -o /auth-example .


FROM node:10.11-alpine as build-frontend
COPY frontend /src/frontend
RUN mkdir -p /src/frontend/public && cp -v /src/frontend/index.html /src/frontend/public/

FROM umputun/baseimage:app-latest

WORKDIR /srv

COPY --from=build-backend /auth-example /srv/auth-example
COPY --from=build-frontend /src/frontend/public/ /srv/web
RUN chown -R app:app /srv

EXPOSE 8080

CMD ["/srv/auth-example"]

