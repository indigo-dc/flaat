#!/bin/bash

# echo -e "---------------------------------------------------------------\n/valid_user"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/valid_user  "Authorization: Bearer `oidc-token deep`"
# done
#
# echo -e "---------------------------------------------------------------\n/valid_user_2"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/valid_user_2  "Authorization: Bearer `oidc-token egi`"
# done
#
# echo -e "---------------------------------------------------------------\n/group_test_kit"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/group_test_kit  "Authorization: Bearer `oidc-token kit`"
#     echo -e "\nshould fail: "
#     http http://localhost:$PORT/group_test_kit  "Authorization: Bearer `oidc-token egi`"
# done
#
# echo -e "---------------------------------------------------------------\n/group_test_iam"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/group_test_iam  "Authorization: Bearer `oidc-token deep`"
#     echo -e "\nshould fail: "
#     http http://localhost:$PORT/group_test_iam  "Authorization: Bearer `oidc-token kit`"
# done
#
# echo -e "---------------------------------------------------------------\n/group_test_hdf"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/group_test_hdf  "Authorization: Bearer `oidc-token login`"
#     echo -e "\nshould fail: "
#     http http://localhost:$PORT/group_test_hdf  "Authorization: Bearer `oidc-token kit`"
# done
#
# echo -e "---------------------------------------------------------------\n/group_test_hdf2"
# for PORT in 8080 8081 8082; do
#     echo -e "\n $PORT"
#     http http://localhost:$PORT/group_test_hdf2  "Authorization: Bearer `oidc-token login`"
#     echo -e "\nshould fail: "
#     http http://localhost:$PORT/group_test_hdf2  "Authorization: Bearer `oidc-token egi`"
# done

echo -e "---------------------------------------------------------------\n/group_test_hdf3"
for PORT in 8080 8081 8082; do 
    echo -e "\n $PORT"
    http http://localhost:$PORT/group_test_hdf3  "Authorization: Bearer `oidc-token login`"
    echo -e "\nshould fail: "
    http http://localhost:$PORT/group_test_hdf3  "Authorization: Bearer `oidc-token egi`"
done
