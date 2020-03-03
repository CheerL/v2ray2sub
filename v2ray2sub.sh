SHELL_FOLDER=$(dirname $(readlink -f "$0"))
CONFIG=${SHELL_FOLDER}/config
OUTPUT_DIR=${SHELL_FOLDER}/output
SS_OUTPUT=${OUTPUT_DIR}/ss
SSR_OUTPUT=${OUTPUT_DIR}/ssr
PYTHON_FILE=${SHELL_FOLDER}/v2ray2sub.py 


if [ ! -d $OUTPUT_DIR ]; then
    mkdir $OUTPUT_DIR
fi
. $CONFIG
python3 $PYTHON_FILE -a $HOST -o $SS_OUTPUT $JSON
python3 $PYTHON_FILE -a $HOST -o $SSR_OUTPUT --ssr $JSON