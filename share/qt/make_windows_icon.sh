#!/bin/bash
# create multiresolution windows icon
ICON_SRC=../../src/qt/res/icons/crypto.png
ICON_DST=../../src/qt/res/icons/crypto.ico
convert ${ICON_SRC} -resize 16x16 crypto-16.png
convert ${ICON_SRC} -resize 32x32 crypto-32.png
convert ${ICON_SRC} -resize 48x48 crypto-48.png
convert crypto-16.png crypto-32.png crypto-48.png ${ICON_DST}

