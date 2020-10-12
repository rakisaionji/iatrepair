FROM fedora:31

LABEL description="Build environment for iatrepair"

RUN yum -y install \
    make \
    zip \
    mingw64-gcc.x86_64 \
    mingw32-gcc.x86_64

RUN mkdir /iatrepair
WORKDIR /iatrepair

COPY iatrepair iatrepair
COPY GNUmakefile GNUmakefile
COPY Module.mk Module.mk

# Building
RUN make