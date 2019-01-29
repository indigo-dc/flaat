#!/bin/bash
PYTHON_VERSION=3
while [ $# -gt 0 ]; do
    case "$1" in
    -2)     PYTHON_VERSION="2";;
    esac
    shift
done

test -d pyve || {
    [ "x$PYTHON_VERSION" == "x3" ] && {
        python3 -m venv pyve || {
            echo -e "\n\nError installing the python3 virtual environment\n"
            exit 2
        }
    [ "x$PYTHON_VERSION" == "x2" ] && {
        virtualenv --python=/usr/bin/python2.7 venv|| {
            echo -e "\n\nError installing the python2.7 virtual environment\n"
            exit 2
        }
    }
}


. pyve/bin/activate

pip install flask requests

export PATH=`pwd`/pyve/bin:$PATH
