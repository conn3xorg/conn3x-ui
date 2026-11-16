# Copyright (c) The Conn3x Authors
# SPDX-License-Identifier: MPL-2.0
#
# The release image, built by GoReleaser from its own binaries. The UI
# clones over https and ssh and runs conn3x, so it needs git, an ssh client
# and CA certificates, which the distroless conn3x image doesn't have; its
# conn3x binary is copied into Alpine instead. Projects can still pin
# another conn3x by path.
FROM ghcr.io/conn3xorg/conn3x:v0.21.0@sha256:b7a40adb5fd43412bd0da567010d2c1a4e1bd86136e2a58ffc0ab007ba2c7434 AS conn3x

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates git openssh-client \
 && adduser -D -u 65532 -h /home/conn3x conn3x \
 && install -d -o conn3x -g conn3x -m 0700 /data
ARG TARGETPLATFORM
COPY --from=conn3x /usr/local/bin/conn3x /usr/local/bin/conn3x
COPY $TARGETPLATFORM/conn3x-ui /usr/local/bin/conn3x-ui
USER conn3x
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/conn3x-ui"]
CMD ["serve", "-listen", "0.0.0.0:8080", "-data", "/data"]
