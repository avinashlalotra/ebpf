#!/bin/bash

cd ..
sudo make all
cd scripts

# start API server in new root shell
gnome-terminal -- bash -c "./server.py; exec bash"

# open tmp shell as root
gnome-terminal -- bash -c "cd ../tmp && exec bash"

# tracing output in new root shell
gnome-terminal -- sudo bash -c "cat /sys/kernel/debug/tracing/trace_pipe; exec bash"

cd ..
sudo ./fentry