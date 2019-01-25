#!/bin/bash

test -d pyve || {
    python3 -m venv pyve || {
        echo -e "\n\nError installing the python3 virtual environment\n"
        exit 2
    }
}

. pyve/bin/activate

pip install flask requests

export PATH=`pwd`/pyve/bin:$PATH
