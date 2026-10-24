FROM ghcr.io/sagernet/sing-box:v1.14.3

RUN apk add --no-cache jq

COPY run.sh parse.jq /
RUN chmod a+x /run.sh

ENTRYPOINT ["/run.sh"]
