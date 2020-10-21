#!/bin/sh

# A table that contains the path of directories to clean
rep_log=("/data0/md")
echo "Cleaning logs - $(date)."

#loop for each path provided by rep_log 
for element in "${rep_log[@]}"
do
   #display the directory
    echo "$element";
    nb_log=$(find "$element" -type f -mtime +30 -name "*.log*"| wc -l)
    if [[ $nb_log != 0 ]]
    then
            find "$element" -type f -mtime +30 -delete
            echo "Successfull!"
    else
            echo "No log to clean !"
    fi
done
