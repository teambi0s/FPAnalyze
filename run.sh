if [ $# -lt 1 ]
then
    echo "Usage ./run.sh <binary name>"
    exit
fi

script_path=$(dirname "$0")
export LD_PRELOAD="./FPAnalyze.so"
./$1
