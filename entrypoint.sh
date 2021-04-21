#!/bin/sh -l

echo $@
pip install -r requirements.txt
python src/main