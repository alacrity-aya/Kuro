#!/bin/bash

sudo tc qdisc add dev v-node2 clsact
sudo tc qdisc add dev v-node2 root fq
sudo tc -s qdisc show dev v-node2
