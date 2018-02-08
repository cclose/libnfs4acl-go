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
const ERROR_NFS4_NOT_SUPPORTED = "operation not supported"
const XATTR_REPLACE_FLAG = 0x2

func Nfs4_getacl_for_path(path string) (acl *NFS4ACL, err error) {
	//Validate the Path and detect directory
	fi, err := os.Stat(path)
	if err != nil {
		//File Not Exists and other errors
		return
	} //implicit else
	isDir := fi.IsDir() //detect if the path is a directory

	return Nfs4GetAcl(path, isDir)
}

//Proxy function that can be used when you already know your path exists and
//if the path is a directory or not. this is helpful when using filepath walks
func Nfs4GetAcl(path string, isDir bool) (acl *NFS4ACL, err error) {
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

	acl, err = XAttrLoad(xattr[:result], isDir)

	//return acl, err
	return

}

func Nfs4_setacl_for_path(path string, acl *NFS4ACL) (err error) {
	//Validate the Path and detect directory
	_, err = os.Stat(path)
	if err != nil {
		//File Not Exists and other errors
		return
	} //implicit else

	return Nfs4SetACL(path, acl)
}

func Nfs4SetACL(path string, acl *NFS4ACL) (err error) {
	err = nfs4_setxattr(path, acl)

	return
}

func nfs4_getxattr(path string, value []byte) (int, error) {
	result, err := unix.Getxattr(path, NFS4_ACL_XATTR, value)
	//check result and err for know problems

	return result, err
}

func nfs4_setxattr(path string, acl *NFS4ACL) error {
	xattr, err := acl.PackXAttr()
	err = unix.Setxattr(path, NFS4_ACL_XATTR, xattr, XATTR_REPLACE_FLAG)

	return err
}
