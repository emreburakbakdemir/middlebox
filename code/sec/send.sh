#!/bin/bash

COVERT_SCRIPT="/code/sec/covert-sender.py"
PYTHON_BIN="python3"

echo "working"

messages=(
    "Hello InsecureNet!"
    "This is a message from SecureNet"
    "Su3knd1Uiknkweevb18!(%nasj)aAujsbu1!Uiknkweevb18!(%nasj)aAujsbu1!!(%nasj)aAujsbu1!!(%nasj)aAujsbu1!"
    "my name is securenet, what is yours?my name is securenet, what is yours?my name is securenet, what is yours?"
    "I love you InsecureNetI love you InsecureNetI love you InsecureNet"
    "I love you InsecureNetI love you InsecureNetI love you InsecureNet"I love you InsecureNetI love you InsecureNetI love you InsecureNet""
    "I love you InsecureNetI love you "
    "I love you InsecureNetI love you InsecureNetI love you I love you InsecureNetI love you InsecureNetI love you InsecureNet"
)

send() {
    local pids=()
    for msg in "${messages[@]}"; do 
        echo message is "$msg" &
        "$PYTHON_BIN" "$COVERT_SCRIPT" --msg "$msg" --bits "4" &
        pids+=( "$!" )
    done

    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

send