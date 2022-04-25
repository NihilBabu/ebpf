from time import sleep
from bcc import BPF

program ="""
    BPF_HASH(syscalls);

    int hello(void *ctx){
        u64 counter = 0;
        u64 key = 56;
        u64 *p;
        
        p = syscalls.lookup(&key);
        if (p != 0) {
            counter = *p;
        }
        counter++;
        syscalls.update(&key, &counter);
        return 0;
    }
"""
print("starting")
b = BPF(text= program)
b.attach_kprobe(event="sys_clone",fn_name="hello")
b.trace_print()
print("here")
while True:
    sleep(3)
    print(b)
    print("\n")
    for k,v in b['syscalls'].items():
        print(k,v)