all: FPAnalyze.c
	gcc -g -Wno-format -fPIC -shared -o FPAnalyze.so FPAnalyze.c -nostartfiles -ldistorm3 -ldl -rdynamic
	cd Samples/ && $(MAKE)

clean:
	rm FPAnalyze.so
	cd Samples/ && $(MAKE) clean
