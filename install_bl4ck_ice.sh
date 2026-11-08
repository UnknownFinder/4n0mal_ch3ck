#!/bin/bash
working_directory=$(pwd)
sudo apt install nftables -y
sudo rm /etc/nftables.conf
sudo cat /$working_directory/bl4ck_ice_v2.conf >> /etc/nftables.conf
sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables
sudo systemctl start nftables
