#!/bin/bash

cd src
ls | while read dir; do
    if [[ -d $dir ]]; then
        cd $dir
        if [[ -f "Makefile" ]]; then
            make 1>/dev/null
            echo "- $dir"
        fi
        cd ..
    fi
done
cd ..