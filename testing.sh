#!/bin/bash

echo -e "\n\nvalid user unity"
http localhost:8080/valid_user "Authorization: Bearer `oidc-token unity`"
echo -e "\n\nvalid user deep"
http localhost:8080/valid_user "Authorization: Bearer `oidc-token deep`"
echo -e "\n\nvalid user kit"
http localhost:8080/valid_user "Authorization: Bearer `oidc-token kit`"
echo -e "\n\nvalid user google"
http localhost:8080/valid_user "Authorization: Bearer `oidc-token google`"

echo -e "\n\ngroup membership hdf"
http localhost:8080/group_test_hdf "Authorization: Bearer `oidc-token unity`"
echo -e "\n\ngroup membership deep"
http localhost:8080/group_test_iam "Authorization: Bearer `oidc-token deep`"
echo -e "\n\ngroup membership kit"
http localhost:8080/group_test_kit "Authorization: Bearer `oidc-token kit`"
echo -e "\n\ngroup membership google (will fail)"
http localhost:8080/group_test_kit "Authorization: Bearer `oidc-token google`"
