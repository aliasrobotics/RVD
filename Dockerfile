FROM ubuntu:20.04

# [Optional] Uncomment this section to install additional OS packages.

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    net-tools python3 python3-pip python3-dev \
    curl gnupg nmap less git gcc-aarch64-linux-gnu wget build-essential

RUN pip3 install Cython

# Copy the parent directory of the current directory into the Docker image
COPY . /workspace/RDV
WORKDIR /workspace/RDV
## SOURCE INSTALL
## Install babeltrace from sources:
#
#         \
#         git build-essential \
#         autoconf locales libglib2.0-dev libtool \
#         bison flex swig python3-dev elfutils libelf-dev \
#         libdw-dev automake libglib2.0-dev \
#         asciidoc xmlto sphinx libpopt-dev less
#         # python3-babeltrace
# RUN locale-gen "en_US.UTF-8"
#
# RUN cd /tmp && git clone https://github.com/efficios/babeltrace -b stable-1.5
# WORKDIR /tmp/babeltrace 
# RUN ./bootstrap && \
#     ./configure --enable-python-bindings --enable-python-plugins --disable-man-pages && \
#     make && \
#     make install
#
# # set env. variable so that babeltrace bindings are found
# ENV LD_LIBRARY_PATH /usr/local/lib