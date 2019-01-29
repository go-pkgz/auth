# docker file to build example
FROM umputun/baseimage:buildgo-latest as build-backend

COPY . /src
WORKDIR /src/_example/backend
RUN go build -o /auth-example .


FROM umputun/baseimage:app-latest

COPY --from=build-backend /auth-example /srv/auth-example
COPY _example/frontend /srv/web
RUN chown -R app:app /srv
EXPOSE 8080
WORKDIR /srv
CMD ["/srv/auth-example"]

