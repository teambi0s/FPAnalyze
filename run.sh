if [ $# -lt 1 ]
then
    echo "Usage ./run.sh <binary name>"
    exit
fi

export LD_PRELOAD="./FPAnalyze.so"
./$1
