#!/bin/bash

test -d pyve || {
    python3 -m venv pyve || {
        echo -e "\n\nError installing the python3 virtual environment\n"
        exit 2
    }
}

. pyve/bin/activate

#pip install flask_oidc PyYAML requests configargparse
pip install PyYAML requests configargparse

#echo -e "Patching flask_oidc"
#cat flask_oidc.patch | patch  -p0 || {
#    echo "Error when patching......."
#}


export PATH=`pwd`/pyve/bin:$PATH
