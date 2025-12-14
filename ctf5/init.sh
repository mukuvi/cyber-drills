#!/bin/bash

# Set up the flag
if [ -z "$DF" ]; then
    # If DF is not set, write the default flag to flag.txt
    echo "FLAG{REAL_FlagG_For_Testing}" > flag.txt
else
    # If DF is set, write its value to flag.txt
    echo "$DF" > flag.txt
fi

# Start the application with pm2
pm2-runtime start app.js --name "virtualEscape"