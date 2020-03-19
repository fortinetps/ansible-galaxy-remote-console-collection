#-----------------------------------------------------------------------------------------
# Copyright (c) Fortinet Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
#-----------------------------------------------------------------------------------------

FROM python:3.7-stretch

# Install pylint
RUN pip3 install pylint

# Configure apt
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get -y install --no-install-recommends apt-utils 2>&1

# Install git, process tools, lsb-release (common in install instructions for CLIs)
RUN apt-get -y install git procps lsb-release

# Install any missing dependencies for enhanced language service
RUN apt-get install -y libicu[0-9][0-9]

RUN mkdir /workspaces
WORKDIR /workspaces

# Install pip2 and Python dependencies from requirements.txt if it exists
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN /usr/bin/python get-pip.py

# Install Python dependencies from requirements.txt if it exists
# COPY .devcontainer/requirements.txt.temp requirements.txt* /workspaces/
# RUN if [ -f "requirements.txt" ]; then pip3 install -r requirements.txt && rm requirements.txt*; fi

# Install ansible's latest devel branch
RUN pip3 install git+https://github.com/ansible/ansible.git@temp-2.10-devel

# Clean up
RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
ENV DEBIAN_FRONTEND=dialog

# Set the default shell to bash rather than sh
ENV SHELL /bin/bash