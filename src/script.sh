#!/usr/bin/env bash


for ((i = 0; i <= 50; i++)); do
    TIMEFORMAT=$'\nBits: '"$i"' | Real %R | User: %U | Sys: %S'

    { time python3 task1.py $i > collision.txt; } 2>> log.txt
done

