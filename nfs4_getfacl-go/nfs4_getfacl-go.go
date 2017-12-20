// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package main

import (
	"flag"
	"fmt"
	"github.com/cclose/libnfs4acl-go"
	"log"
)

func main() {
	recursive := flag.Bool("recursive", false, "recurse into directories")
	omitheader := flag.Bool("omit-header", false, "omit header for each path")

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
	}

	for i := 0; i < flag.NArg(); i++ {
		filePath := flag.Arg(i)
		acls, err := nfs4acl.GetFACL(filePath, *recursive, !*omitheader)
		if err != nil {
			log.Fatal(err)
		} else {
			fmt.Printf("yay!")
			fmt.Printf("%+v\n", acls)
			//nfs4acl.PrintACL(acls)
		}
	}
}
