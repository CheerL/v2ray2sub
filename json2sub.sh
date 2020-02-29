SHELL_FOLDER=$(dirname $(readlink -f "$0"))
. $SHELL_FOLDER/config

python3 $SHELL_FOLDER/json2sub.py -a $HOST -o $SHELL_FOLDER/output/index.html $JSON