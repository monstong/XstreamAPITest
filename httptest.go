package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {

	port := flag.String("p","8100","port of serve on ")
	directory := flag.String("d",".","directory current")
	flag.Parse()

	http.Handle("/",http.FileServer(http.Dir(*directory)))

	log.Print("WEB TEST Virtu VM 8100 port, Hello Mr.kwon")
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
