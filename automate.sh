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

echo 'Git is updated'
