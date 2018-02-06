// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package nfs4acl

import (
	"encoding/binary"
	"errors"
	"unsafe"
	//"bytes"
	//"fmt"
)

//Size of xattr packing atoms (uint32) in bytes
const (
	//This could probably be a constant '4' but i feel safer measuring
	ATOM_SIZE = int(unsafe.Sizeof(uint32(0)))
)

//Default ACL Who strings
const (
	NFS4_ACL_WHO_OWNER_STRING    = "OWNER@"
	NFS4_ACL_WHO_GROUP_STRING    = "GROUP@"
	NFS4_ACL_WHO_EVERYONE_STRING = "EVERYONE@"
)

//ACL Who string enums
const (
	NFS4_ACL_WHO_NAMED = iota
	NFS4_ACL_WHO_OWNER
	NFS4_ACL_WHO_GROUP
	NFS4_ACL_WHO_EVERYONE
)

//ACE Type enums
const (
	NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE = iota
	NFS4_ACE_ACCESS_DENIED_ACE_TYPE
	NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE
	NFS4_ACE_SYSTEM_ALARM_ACE_TYPE
)

//ACE Type display characters
const (
	TYPE_ALLOW = 'A'
	TYPE_DENY  = 'D'
	TYPE_AUDIT = 'U'
	TYPE_ALARM = 'L'
)

//ACE Flags binary values
//Each value is the next most significant bit, shifts 1 place left incrementally
const (
	NFS4_ACE_FILE_INHERIT_ACE      = 1 << iota //0x0001
	NFS4_ACE_DIRECTORY_INHERIT_ACE             //0x0010  etc
	NFS4_ACE_NO_PROPAGATE_INHERIT_ACE
	NFS4_ACE_INHERIT_ONLY_ACE
	NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG
	NFS4_ACE_FAILED_ACCESS_ACE_FLAG
	NFS4_ACE_IDENTIFIER_GROUP
	NFS4_ACE_OWNER
	NFS4_ACE_GROUP
	NFS4_ACE_EVERYONE
)

//ACE Flags display characters
const (
	FLAG_FILE_INHERIT         = 'f'
	FLAG_DIR_INHERIT          = 'd'
	FLAG_NO_PROPAGATE_INHERIT = 'n'
	FLAG_INHERIT_ONLY         = 'i'
	FLAG_SUCCESSFUL_ACCESS    = 'S'
	FLAG_FAILED_ACCESS        = 'F'
	FLAG_GROUP                = 'g'
	FLAG_OWNER_AT             = 'O'
	FLAG_GROUP_AT             = 'G'
	FLAG_EVERYONE_AT          = 'E'
)

//ACE access mask values
//Would use the Iota shift as above, but there's enough duplicated variables here
const (
	NFS4_ACE_READ_DATA         = 0x00000001
	NFS4_ACE_LIST_DIRECTORY    = 0x00000001
	NFS4_ACE_WRITE_DATA        = 0x00000002
	NFS4_ACE_ADD_FILE          = 0x00000002
	NFS4_ACE_APPEND_DATA       = 0x00000004
	NFS4_ACE_ADD_SUBDIRECTORY  = 0x00000004
	NFS4_ACE_READ_NAMED_ATTRS  = 0x00000008
	NFS4_ACE_WRITE_NAMED_ATTRS = 0x00000010
	NFS4_ACE_EXECUTE           = 0x00000020
	NFS4_ACE_DELETE_CHILD      = 0x00000040
	NFS4_ACE_READ_ATTRIBUTES   = 0x00000080
	NFS4_ACE_WRITE_ATTRIBUTES  = 0x00000100
	NFS4_ACE_DELETE            = 0x00010000
	NFS4_ACE_READ_ACL          = 0x00020000
	NFS4_ACE_WRITE_ACL         = 0x00040000
	NFS4_ACE_WRITE_OWNER       = 0x00080000
	NFS4_ACE_SYNCHRONIZE       = 0x00100000
)

const (
	PERM_READ_DATA   = 'r'
	PERM_WRITE_DATA  = 'w'
	PERM_APPEND_DATA = 'a'

	PERM_LIST_DIR      = PERM_READ_DATA
	PERM_CREATE_FILE   = PERM_WRITE_DATA
	PERM_CREATE_SUBDIR = PERM_APPEND_DATA
	PERM_DELETE_CHILD  = 'D'

	PERM_DELETE           = 'd'
	PERM_EXECUTE          = 'x'
	PERM_READ_ATTR        = 't'
	PERM_WRITE_ATTR       = 'T'
	PERM_READ_NAMED_ATTR  = 'n'
	PERM_WRITE_NAMED_ATTR = 'N'
	PERM_READ_ACL         = 'c'
	PERM_WRITE_ACL        = 'C'
	PERM_WRITE_OWNER      = 'o'
	PERM_SYNCHRONIZE      = 'y'

	//PERM_GENERIC_READ    = 'R'
	//PERM_GENERIC_WRITE   = 'W'
	//PERM_GENERIC_EXECUTE = 'X'
)

type NFS4ACL struct {
	isDirectory bool
	aceList     []*NFS4ACE
}

func XAttrLoad(value []byte, isDir bool) (newACL *NFS4ACL, err error) {
	newACL = &NFS4ACL{
		isDirectory: isDir,
	}

	//This could probably be a constant '4' but i feel safer measuring
	curAtom := int(0)
	maxAtom := len(value)
	if maxAtom < ATOM_SIZE {
		err = errors.New("invalid input buffer 'value'")
		return
	}

	//value is an array of bytes
	//the ACL data is stored as 32bit ints in this array
	//we read this data by stepping 1 32bit at a time through the array
	//ACL Packing structure:
	// [numAces]{ACE}{ACE}{ACE}

	//We make sure we convert FROM network byte order as a uint32
	numAces := int(binary.BigEndian.Uint32(value[curAtom:]))

	//increment our pointer to the next uint32
	curAtom += ATOM_SIZE

	for curAce := 0; curAce < numAces; curAce++ {
		//sanity check our boundaries
		if curAtom >= maxAtom {
			err = errors.New("buffer overflow")
			return
		}

		//ACE Packing structure:
		// [type][flag][AccessMask][who_Len][who_str]{whoLen}

		//verify there's room in the buffer for the next 4 uint32s
		if (curAtom + (ATOM_SIZE * 4)) >= maxAtom {
			err = errors.New("buffer overflow")
			return
		}

		//retrieve type
		aceType := binary.BigEndian.Uint32(value[curAtom:])
		curAtom += ATOM_SIZE //increment ptr

		//retrieve flag
		aceFlag := binary.BigEndian.Uint32(value[curAtom:])
		curAtom += ATOM_SIZE //increment ptr

		//retrieve access mask
		aceMask := binary.BigEndian.Uint32(value[curAtom:])
		curAtom += ATOM_SIZE //increment ptr

		//get the size, in bytes, of the Who string
		whoLen := int(binary.BigEndian.Uint32(value[curAtom:]))
		curAtom += ATOM_SIZE //increment ptr

		//retrieve the Who string
		aceWho := string(value[curAtom:(whoLen + curAtom)])
		//and increment the pointer
		curAtom += AceWhoStringAtomLength(whoLen)

		//create a new ACE struct and append it to our ACL struct
		newACE := NewNFS4ACE(aceType, aceFlag, aceMask, aceWho)
		newACL.aceList = append(newACL.aceList, newACE)
	}

	return //returns newACL, err
}
func (acl *NFS4ACL) PrintACL(verbose bool) error {
	for _, ace := range acl.aceList {
		ace.PrintACE(verbose, acl.isDirectory)
	}
	return nil
}

func (acl *NFS4ACL) XAttrSize() (xAttrSize int) {
	//ACL Packing structure:
	// [num_aces]{ACE}{ACE}{ACE}
	//ACE Counter, 1 atom to count the # of aces
	xAttrSize = ATOM_SIZE

	//ACE Packing structure:
	// [type][flag][AccessMask][who_Len][who_str]{who_len}
	for _, ace := range acl.aceList {
		//each ACE has 4 atom's to store type, flag, access mask and wholen
		xAttrSize += ATOM_SIZE * 4
		//and add space for the whostring
		xAttrSize += AceWhoStringAtomLength(len(ace.Who))
	}

	//and that's all
	return
}

func (acl *NFS4ACL) PackXAttr() (xattr []byte, err error) {
	err = nil
	aclSize := acl.XAttrSize()
	xattr = make([]byte, aclSize, aclSize)
	currAtom := int(0)

	//ACL Packing structure:
	// [num_aces]{ACE}{ACE}{ACE}
	// pack number of aces as a uint32 into the buffer
	// use BigEndian for Network Byte order
	binary.BigEndian.PutUint32(xattr[currAtom:], uint32(len(acl.aceList)))
	currAtom += ATOM_SIZE

	//ACE Packing structure:
	// [type][flag][AccessMask][who_Len][who_str]{who_len}
	for _, ace := range acl.aceList {
		//write ace type
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.AceType)
		currAtom += ATOM_SIZE
		//write ace Flags
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.Flags)
		currAtom += ATOM_SIZE
		//write ace access mask
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.AccessMask)
		currAtom += ATOM_SIZE
		//write ace whoLen
		whoLen := len(ace.Who)
		binary.BigEndian.PutUint32(xattr[currAtom:], uint32(whoLen))
		currAtom += ATOM_SIZE

		//Write the Who string into the data
		copy(xattr[currAtom:], ace.Who)
		currAtom += AceWhoStringAtomLength(whoLen)
	}

	return
}

func (acl *NFS4ACL) ApplyAccessMask(accessMask uint32) {
	for _, ace := range acl.aceList {
		ace.applyAccessMask(accessMask)
	}
}

// Similar to applyAccessMaskByWho, but the whoType matching is faster if usable
func (acl *NFS4ACL) ApplyAccessMaskByWhoType(accessMask uint32, whoType uint) error {
	if whoType == NFS4_ACL_WHO_NAMED {
		return errors.New("named who not allowed")
	} else if whoType < NFS4_ACL_WHO_NAMED || whoType > NFS4_ACL_WHO_EVERYONE {
		return errors.New("unsupported who type")
	}

	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only apply if the whotype matches
		if ace.WhoType == whoType {
			ace.applyAccessMask(accessMask)
		}
	}

	return nil
}

func (acl *NFS4ACL) ApplyAccessMaskByWho(accessMask uint32, who string) error {
	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only apply if the who matches
		if ace.Who == who {
			ace.applyAccessMask(accessMask)
		}
	}

	return nil
}

func (acl *NFS4ACL) RemoveAccessMask(accessMask uint32) {
	for _, ace := range acl.aceList {
		ace.removeAccessMask(accessMask)
	}
}

// Similar to removeAccessMaskByWho, but the whoType matching is faster if usable
func (acl *NFS4ACL) RemoveAccessMaskByWhoType(accessMask uint32, whoType uint) error {
	if whoType == NFS4_ACL_WHO_NAMED {
		return errors.New("named who not allowed")
	} else if whoType < NFS4_ACL_WHO_NAMED || whoType > NFS4_ACL_WHO_EVERYONE {
		return errors.New("unsupported who type")
	}

	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only remove if the whotype matches
		if ace.WhoType == whoType {
			ace.removeAccessMask(accessMask)
		}
	}

	return nil
}

func (acl *NFS4ACL) RemoveAccessMaskByWho(accessMask uint32, who string) error {
	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only remove if the who matches
		if ace.Who == who {
			ace.removeAccessMask(accessMask)
		}
	}

	return nil
}

func (acl *NFS4ACL) SetAccessMask(accessMask uint32) {
	for _, ace := range acl.aceList {
		ace.setAccessMask(accessMask)
	}
}

// Similar to setAccessMaskByWho, but the whoType matching is faster if usable
func (acl *NFS4ACL) SetAccessMaskByWhoType(accessMask uint32, whoType uint) error {
	if whoType == NFS4_ACL_WHO_NAMED {
		return errors.New("named who not allowed")
	} else if whoType < NFS4_ACL_WHO_NAMED || whoType > NFS4_ACL_WHO_EVERYONE {
		return errors.New("unsupported who type")
	}

	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only set if the whotype matches
		if ace.WhoType == whoType {
			ace.setAccessMask(accessMask)
		}
	}

	return nil
}

func (acl *NFS4ACL) SetAccessMaskByWho(accessMask uint32, who string) error {
	//iterate our ace's
	for _, ace := range acl.aceList {
		//and only set if the who matches
		if ace.Who == who {
			ace.setAccessMask(accessMask)
		}
	}

	return nil
}
