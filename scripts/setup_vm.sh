#!/bin/bash

docker run -it --rm \
  -p 8428:8428 \
  -v $/home/alacrity/work/go/kuro/local-data/ \
  victoriametrics/victoria-metrics:latest
