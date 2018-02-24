#!/bin/bash

GUSER="bilucent"
GPASS='Gaghbij12'



suffix=$(date +%s)
echo $suffix
set date [clock format $now -format {%b-%d}]
echo $date



git add .
git commit -m 'commit $data'
git push


