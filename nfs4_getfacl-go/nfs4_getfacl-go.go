// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package main

import (
	"flag"
	//"fmt"
	"github.com/cclose/libnfs4acl-go"
	"log"
)

func main() {
	//recursive := flag.Bool("recursive", false, "recurse into directories")
	//omitheader := flag.Bool("omit-header", false, "omit header for each path")
	verbose := flag.Bool("verbose", false, "verbosity of output")

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
	}

	for i := 0; i < flag.NArg(); i++ {
		filePath := flag.Arg(i)
		acls, err := nfs4acl.Nfs4_getacl_for_path(filePath)
		if err != nil {
			log.Fatal(err)
		} else {
			acls.Nfs4_print_acl(*verbose)
		}
	}
}
