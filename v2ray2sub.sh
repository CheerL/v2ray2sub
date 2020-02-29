SHELL_FOLDER=$(dirname $(readlink -f "$0"))
CONFIG=${SHELL_FOLDER}/config
OUTPUT_DIR=${SHELL_FOLDER}/output
OUTPUT=${OUTPUT_DIR}/index.html
PYTHON_FILE=${SHELL_FOLDER}/v2ray2sub.py 


if [ ! -d $OUTPUT_DIR ]; then
    mkdir $OUTPUT_DIR
fi
. $CONFIG
python3 $PYTHON_FILE -a $HOST -o $OUTPUT $JSON