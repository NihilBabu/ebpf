package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"fmt"
	"os"
	"os/signal"
)

func main() {

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	defer b.Close()

	must(b.BPFLoadObject())

	prog, err := b.GetProgram("hello")
	must(err)
	// _, err = p.AttachKprobe("__x64_sys_execve")
	_, err = prog.AttachRawTracepoint("sys_enter")
	must(err)

	e := make(chan []byte, 300)
	p, err := b.InitPerfBuf("gotopia", e, nil, 1024)
	must(err)
	p.Start()

	c := make(map[string]int, 350)
	go func() {
		for data := range e {
			comm := string(data)
			// fmt.Printf("got %s\n", comm)
			c[comm]++
		}
	}()

	<-sig

	fmt.Println("cleaning up")

	for comm, val := range c {
		fmt.Printf("%s : %d\n", comm, val)
	}
	p.Stop()

}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
