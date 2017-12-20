// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package nfs4acl

import (
	"fmt"
	"golang.org/x/sys/unix"
	//"unsafe"
)

const NFS4_ACL_XATTR string = "system.nfs4_acl"

//type NFS4_ACL struct {
//	a C.nfs4_acl
//}

func GetFACL(path string, recursive, header bool) (string, error) {
	acls, error := nfs4_getacl_for_path(path)

	return acls, error
}

func nfs4_getacl_for_path(path string) (string, error) {
	fmt.Println("Called getacl_for_path\n")
	//Validate the Path and detect directory
	// Fetch extended attributes for path
	//result := nfs4_getxattr(path, NFS4_ACL_XATTR, nil)
	result, error := unix.Getxattr(path, NFS4_ACL_XATTR, nil)
	fmt.Printf("xattr will be %d bits\n", result)

	xattr := make([]byte, result)
	result, error = unix.Getxattr(path, NFS4_ACL_XATTR, xattr)
	
	fmt.Printf("got back %d bits\n", result)
	fmt.Printf("xattr is %+v\n", xattr)

	//return acls, error
	return "yay", error
}

/*
func nfs4_getxattr() () {

}

func PrintACL(acl *C.struct_nfs4_acl) (string, error) {
	

}

func PrintACE(ace *C.struct_nfs4_ace, isdir uint32) {
	var result int
	var who *char
	var buf char[16]

}
*/
