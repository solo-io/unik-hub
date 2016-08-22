#!/usr/bin/env bash

set -e

sudo add-apt-repository ppa:ubuntu-lxc/lxd-stable -y
sudo apt-get update
sudo apt-get install golang git -y

export GOPATH=${HOME}/go
export PATH=${PATH}:${HOME}/go/bin/

mkdir -p ${GOPATH}/src/github.com/emc-advanced-dev/ && cd ${GOPATH}/src/github.com/emc-advanced-dev/
git clone https://github.com/emc-advanced-dev/unik-hub && cd unik-hub
go install

cd ${HOME}
sudo tee /etc/systemd/system/unikhub.service <<EOF
[Unit]
Description=Unik Hub

[Service]
Environment=AWS_ACCESS_KEY_ID=$1
Environment=AWS_SECRET_ACCESS_KEY=$2
Environment=AWS_REGION=$3
Environment=AWS_BUCKET=$4
Type=simple
ExecStart=${HOME}/go/bin/unik-hub

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable unikhub.service
sudo systemctl start unikhub.service