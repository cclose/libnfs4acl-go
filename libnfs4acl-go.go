// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package nfs4acl

import (
	//"fmt"
	"golang.org/x/sys/unix"
	"os"
	//"unsafe"
)

const NFS4_ACL_XATTR = "system.nfs4_acl"
const XATTR_REPLACE_FLAG = 0x2

func Nfs4_getacl_for_path(path string) (acl *Nfs4_acl, err error) {
	//Validate the Path and detect directory
	fi, err := os.Stat(path)
	if err != nil {
		//File Not Exists and other errors
		return
	} //implicit else
	isDir := fi.IsDir() //detect if the path is a directory

	//get the size of our value buffer
	var result int
	result, err = nfs4_getxattr(path, nil)
	if err != nil {
		return
	}

	xattr := make([]byte, result, result)
	result, err = nfs4_getxattr(path, xattr)
	if err != nil {
		return
	}

	acl, err = nfs4_xattr_load(xattr[:result], isDir)

	//return acl, err
	return
}

func Nfs4_setacl_for_path(path string, acl *Nfs4_acl) (err error) {
	//Validate the Path and detect directory
	_, err = os.Stat(path)
	if err != nil {
		//File Not Exists and other errors
		return
	} //implicit else

	err = nfs4_setxattr(path, acl)

	return
}

func nfs4_getxattr(path string, value []byte) (int, error) {
	result, err := unix.Getxattr(path, NFS4_ACL_XATTR, value)
	//check result and err for know problems

	return result, err
}

func nfs4_setxattr(path string, acl *Nfs4_acl) error {
	xattr, err := acl.PackXAttr()
	err = unix.Setxattr(path, NFS4_ACL_XATTR, xattr, XATTR_REPLACE_FLAG)

	return err
}
