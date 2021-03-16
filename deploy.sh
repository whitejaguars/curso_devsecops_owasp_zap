#!/bin/bash
if [[ ! -d "venv" ]];
then
    echo "[!] No virtual environment found"
    echo "[!] Add python virtual environment"
    sudo python3 -m venv venv/
    pythonpip="venv/bin/pip"
    if [[ -f "$pythonpip" ]]; then
        echo "[!] Virtual environment created"
    else
        echo "[X] Unable to create the virtual environment, aborting"
        exit 1
    fi
    sudo venv/bin/pip install -r requirements.txt
fi