package main

import (
	"io"
	"net"
	"net/http"
	"os"
)

func main() {
	go func() { // TCP echo for the L4 benchmark
		l, _ := net.Listen("tcp", "127.0.0.1:"+os.Args[2])
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	http.ListenAndServe("127.0.0.1:"+os.Args[1], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello from backend\n"))
	}))
}
