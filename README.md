# FPAnalyze

Utility to dump function pointers by teambi0s

## Installation

+ Dependencies:

```sh
apt-get install -y libdistorm3-dev
apt install make 
apt-get -y install gcc
```

+ Cloning:

```sh
git clone https://gitlab.com/teambi0s/pwning.git
cd pwning/tools/Function_Pointer
make
```

+ Running:

```sh
./run.sh <binary_name>
```

## Examples

`0x1245 : 0x1545 (binary)`
Here the pointer was found at `0x1245` from base of binary and it was called by an instruction at an offset of `0x1545`.

`0x1245 (binary)`
Here the pointer was found at `0x1245` from base of binary but tool couldn't find the instruction.

`0x1245 : 0x1545 (libc)`
Here the pointer was found at `0x1245` from base of libc and it was called by an instruction at an offset of `0x1545`.

`0x1245 (libc)`
Here the pointer was found at `0x1245` from base of binary but tool couldn't find the instruction.

##### Other versions of linux

+ You can either preload the libc along with the tool or use the Dockerfile provided.

+ Change the version inside the Dockerfile to your desired one and do `./docker.sh`.

+ To preload the libc with tool, use `patchelf` utility to use the loader of the required libc and then edit the `run.sh` to preload the libc along the the tool.
