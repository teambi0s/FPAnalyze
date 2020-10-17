src = $(wildcard *.c)
obj = $(src:.c=.out)


all: $(obj)

$(obj): %.out: %.c
	gcc -no-pie -o $@ $<

clean:
	rm -r *.out
