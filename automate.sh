#!/bin/bash

GUSER="bilucent"
NOW=$(date +"%Y-%m-%d-%H-%M")
echo 'time is $NOW'

echo 'your commit message?'
read COMMITMESSAGE
echo $COMMITMESSAGE

read -s -p "Enter GIT Password: " mypassword

echo 'Git work now'
git add .
git commit -m 'commit $date'
git push
expect \"ser"\
send $GUSER
expect \"assword:\"
send \"$mypassword\r\"
echo 'Git is updated'
