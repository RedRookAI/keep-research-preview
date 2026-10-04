FROM node@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5

# Build prerequisites exist only in this image, never on the shared host.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    gcc libc6-dev libcap-dev meson ninja-build pkg-config git python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD https://github.com/containers/bubblewrap/releases/download/v0.13.0/bubblewrap-0.13.0.tar.xz /build/bubblewrap-0.13.0.tar.xz
RUN printf '%s\n' '4734237473c0e5d695e4e9034a34e43b2dbf5164655bd13fa59ae376b2b7a765  bubblewrap-0.13.0.tar.xz' | sha256sum -c - \
    && tar -xf bubblewrap-0.13.0.tar.xz
ENV SOURCE_DATE_EPOCH=1790077200
ENV CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE"
ENV LDFLAGS="-Wl,-z,relro,-z,now -pie"
RUN meson setup output bubblewrap-0.13.0 --buildtype=release \
    --prefix=/opt/keep/bubblewrap/0.13.0 -Dbwrapdir=/opt/keep/bubblewrap/0.13.0 \
    -Dselinux=disabled -Dman=disabled -Dbash_completion=disabled \
    -Dzsh_completion=disabled -Dtests=false \
    && meson compile -C output -j 1 \
    && meson install -C output \
    && /opt/keep/bubblewrap/0.13.0/bwrap --version \
    && sha256sum /opt/keep/bubblewrap/0.13.0/bwrap > /build/bubblewrap-binary.sha256 \
    && dpkg-query -W > /build/build-packages.txt
