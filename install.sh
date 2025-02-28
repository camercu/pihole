#!/bin/bash

sudo apt update && sudo apt upgrade -y
sudo apt install -y neovim unbound
sudo apt autoremove -y && sudo apt autoclean -y

curl -sSL https://install.pi-hole.net | sudo bash
