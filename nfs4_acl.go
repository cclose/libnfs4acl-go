// Copyright (c) 2017 Cory Close. See LICENSE file.

// Package nfs4_acl provides an interface to NFSv4 Access Control Lists

package nfs4acl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
	//"golang.org/x/sys/unix"
)

//Size of xattr packing atoms (uint32) in bytes
const (
	//This could probably be a constant '4' but i feel safer measuring
	atomSize = int(unsafe.Sizeof(uint32(0)))
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

type Nfs4_acl struct {
	is_directory bool
	ace_list     []*Nfs4_ace
}

type Nfs4_ace struct {
	acetype     uint32
	whotype     uint
	who         string
	flags       uint32
	access_mask uint32
}

//Nfs4_ace struct constructor
func NewNfs4_ace(acetype, flag, mask uint32, who string) *Nfs4_ace {
	return &Nfs4_ace{
		acetype:     acetype,
		who:         who,
		whotype:     nfs4_ace_get_whotype(who),
		flags:       flag,
		access_mask: mask,
	}
}

func nfs4_xattr_load(value []byte, is_dir bool) (new_acl *Nfs4_acl, err error) {
	new_acl = &Nfs4_acl{
		is_directory: is_dir,
	}

	//This could probably be a constant '4' but i feel safer measuring
	atom_size := int(unsafe.Sizeof(uint32(0)))
	cur_atom := int(0)
	max_atom := len(value)
	if max_atom < atom_size {
		err = errors.New("Invalid input buffer 'value'")
		return
	}

	//value is an array of bytes
	//the ACL data is stored as 32bit ints in this array
	//we read this data by stepping 1 32bit at a time through the array
	//ACL Packing structure:
	// [num_aces]{ACE}{ACE}{ACE}

	//We make sure we convert FROM network byte order as a uint32
	num_aces := int(binary.BigEndian.Uint32(value[cur_atom:]))

	//increment our pointer to the next uint32
	cur_atom += atom_size

	for cur_ace := 0; cur_ace < num_aces; cur_ace++ {
		//sanity check our boundaries
		if cur_atom >= max_atom {
			err = errors.New("Buffer overflow")
			return
		}

		//ACE Packing structure:
		// [type][flag][access_mask][who_Len][who_str]{who_len}

		//verify there's room in the buffer for the next 4 uint32s
		if (cur_atom + (atom_size * 4)) >= max_atom {
			err = errors.New("Buffer overflow")
			return
		}

		//retrieve type
		ace_type := binary.BigEndian.Uint32(value[cur_atom:])
		cur_atom += atom_size //increment ptr

		//retrieve flag
		ace_flag := binary.BigEndian.Uint32(value[cur_atom:])
		cur_atom += atom_size //increment ptr

		//retrieve access mask
		ace_mask := binary.BigEndian.Uint32(value[cur_atom:])
		cur_atom += atom_size //increment ptr

		//get the size, in bytes, of the who string
		who_len := int(binary.BigEndian.Uint32(value[cur_atom:]))
		cur_atom += atom_size //increment ptr

		//retrieve the who string
		ace_who := string(value[cur_atom:(who_len + cur_atom)])
		//and increment the pointer
		cur_atom += Nfs4ACEWhoStringAtomLength(who_len)

		//create a new ACE struct and append it to our ACL struct
		new_ace := NewNfs4_ace(ace_type, ace_flag, ace_mask, ace_who)
		new_acl.ace_list = append(new_acl.ace_list, new_ace)
	}

	return //returns new_acl, err
}

func nfs4_ace_get_whotype(who string) uint {
	switch who {
	case NFS4_ACL_WHO_OWNER_STRING:
		return NFS4_ACL_WHO_OWNER
	case NFS4_ACL_WHO_GROUP_STRING:
		return NFS4_ACL_WHO_GROUP
	case NFS4_ACL_WHO_EVERYONE_STRING:
		return NFS4_ACL_WHO_EVERYONE
	} //implicit default/else

	return NFS4_ACL_WHO_NAMED
}

func (acl *Nfs4_acl) Nfs4_print_acl(verbose bool) error {
	for _, ace := range acl.ace_list {
		ace.Nfs4_print_ace(verbose, acl.is_directory)
	}
	return nil
}

func (ace *Nfs4_ace) Nfs4_print_ace(verbose, isDir bool) error {
	//Create print buffer
	var buffer bytes.Buffer

	//Prepare Ace Type
	if verbose {
		switch ace.acetype {
		case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
			buffer.WriteString("ALLOW")
		case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
			buffer.WriteString("DENY")
		case NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE:
			buffer.WriteString("AUDIT")
		case NFS4_ACE_SYSTEM_ALARM_ACE_TYPE:
			buffer.WriteString("ALARM")
		}
	} else {
		switch ace.acetype {
		case NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE:
			buffer.WriteRune(TYPE_ALLOW)
		case NFS4_ACE_ACCESS_DENIED_ACE_TYPE:
			buffer.WriteRune(TYPE_DENY)
		case NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE:
			buffer.WriteRune(TYPE_AUDIT)
		case NFS4_ACE_SYSTEM_ALARM_ACE_TYPE:
			buffer.WriteRune(TYPE_ALARM)
		}
	}
	buffer.WriteRune(':')

	//Prepare Ace Flags
	if ace.flags&NFS4_ACE_FILE_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_FILE_INHERIT)
	}
	if ace.flags&NFS4_ACE_DIRECTORY_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_DIR_INHERIT)
	}
	if ace.flags&NFS4_ACE_NO_PROPAGATE_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_NO_PROPAGATE_INHERIT)
	}
	if ace.flags&NFS4_ACE_INHERIT_ONLY_ACE != 0 {
		buffer.WriteRune(FLAG_INHERIT_ONLY)
	}
	if ace.flags&NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG != 0 {
		buffer.WriteRune(FLAG_SUCCESSFUL_ACCESS)
	}
	if ace.flags&NFS4_ACE_FAILED_ACCESS_ACE_FLAG != 0 {
		buffer.WriteRune(FLAG_FAILED_ACCESS)
	}
	if ace.flags&NFS4_ACE_IDENTIFIER_GROUP != 0 {
		buffer.WriteRune(FLAG_GROUP)
	}
	if ace.flags&NFS4_ACE_OWNER != 0 {
		buffer.WriteRune(FLAG_OWNER_AT)
	}
	if ace.flags&NFS4_ACE_GROUP != 0 {
		buffer.WriteRune(FLAG_GROUP_AT)
	}
	if ace.flags&NFS4_ACE_EVERYONE != 0 {
		buffer.WriteRune(FLAG_EVERYONE_AT)
	}
	buffer.WriteRune(':')

	//Prepare Ace WHO
	buffer.WriteString(ace.who)
	buffer.WriteRune(':')

	//Prepare Ace Mask
	if isDir {
		if ace.access_mask&NFS4_ACE_LIST_DIRECTORY != 0 {
			buffer.WriteRune(PERM_LIST_DIR)
		}
		if ace.access_mask&NFS4_ACE_ADD_FILE != 0 {
			buffer.WriteRune(PERM_CREATE_FILE)
		}
		if ace.access_mask&NFS4_ACE_ADD_SUBDIRECTORY != 0 {
			buffer.WriteRune(PERM_CREATE_SUBDIR)
		}
		if ace.access_mask&NFS4_ACE_DELETE_CHILD != 0 {
			buffer.WriteRune(PERM_DELETE_CHILD)
		}
	} else {
		if ace.access_mask&NFS4_ACE_READ_DATA != 0 {
			buffer.WriteRune(PERM_READ_DATA)
		}
		if ace.access_mask&NFS4_ACE_WRITE_DATA != 0 {
			buffer.WriteRune(PERM_WRITE_DATA)
		}
		if ace.access_mask&NFS4_ACE_APPEND_DATA != 0 {
			buffer.WriteRune(PERM_APPEND_DATA)
		}
	}
	if ace.access_mask&NFS4_ACE_DELETE != 0 {
		buffer.WriteRune(PERM_DELETE)
	}
	if ace.access_mask&NFS4_ACE_EXECUTE != 0 {
		buffer.WriteRune(PERM_EXECUTE)
	} else {
		fmt.Println("no execute perms!")
	}
	if ace.access_mask&NFS4_ACE_READ_ATTRIBUTES != 0 {
		buffer.WriteRune(PERM_READ_ATTR)
	}
	if ace.access_mask&NFS4_ACE_WRITE_ATTRIBUTES != 0 {
		buffer.WriteRune(PERM_WRITE_ATTR)
	}
	if ace.access_mask&NFS4_ACE_READ_NAMED_ATTRS != 0 {
		buffer.WriteRune(PERM_READ_NAMED_ATTR)
	}
	if ace.access_mask&NFS4_ACE_WRITE_NAMED_ATTRS != 0 {
		buffer.WriteRune(PERM_WRITE_NAMED_ATTR)
	}
	if ace.access_mask&NFS4_ACE_READ_ACL != 0 {
		buffer.WriteRune(PERM_READ_ACL)
	}
	if ace.access_mask&NFS4_ACE_WRITE_ACL != 0 {
		buffer.WriteRune(PERM_WRITE_ACL)
	}
	if ace.access_mask&NFS4_ACE_WRITE_OWNER != 0 {
		buffer.WriteRune(PERM_WRITE_OWNER)
	}
	if ace.access_mask&NFS4_ACE_SYNCHRONIZE != 0 {
		buffer.WriteRune(PERM_SYNCHRONIZE)
	}

	fmt.Println(buffer.String())
	return nil
}

func (acl *Nfs4_acl) XAttrSize() (xAttrSize int) {
	//ACL Packing structure:
	// [num_aces]{ACE}{ACE}{ACE}
	//ACE Counter, 1 atom to count the # of aces
	xAttrSize = atomSize

	//ACE Packing structure:
	// [type][flag][access_mask][who_Len][who_str]{who_len}
	for _, ace := range acl.ace_list {
		//each ACE has 4 atom's to store type, flag, access mask and wholen
		xAttrSize += atomSize * 4
		//and add space for the whostring
		xAttrSize += Nfs4ACEWhoStringAtomLength(len(ace.who))
	}

	//and that's all
	return
}

func (acl *Nfs4_acl) PackXAttr() (xattr []byte, err error) {
	err = nil
	aclSize := acl.XAttrSize()
	xattr = make([]byte, aclSize, aclSize)
	currAtom := int(0)


	//ACL Packing structure:
	// [num_aces]{ACE}{ACE}{ACE}
	// pack number of aces as a uint32 into the buffer
	// use BigEndian for Network Byte order
	binary.BigEndian.PutUint32(xattr[currAtom:], uint32(len(acl.ace_list)))
	currAtom += atomSize

	//ACE Packing structure:
	// [type][flag][access_mask][who_Len][who_str]{who_len}
	for _, ace := range acl.ace_list {
		//write ace type
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.acetype)
		currAtom += atomSize
		//write ace flags
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.flags)
		currAtom += atomSize
		//write ace access mask
		binary.BigEndian.PutUint32(xattr[currAtom:], ace.access_mask)
		currAtom += atomSize
		//write ace whoLen
		whoLen := len(ace.who)
		binary.BigEndian.PutUint32(xattr[currAtom:], uint32(whoLen))
		currAtom += atomSize

		//Write the who string into the data
		copy(xattr[currAtom:], ace.who)
		currAtom += Nfs4ACEWhoStringAtomLength(whoLen)
	}

	return
}

func Nfs4ACEWhoStringAtomLength(whoLength int) int {
	//since the who string isn't necessarily uint32 sized
	//we need to find out how many uint32's, rounding up, it used
	//so we can properly increment the pointer
	// get the size of our who string, rounded down to the nears atom
	whoIncrement := int(whoLength/atomSize) * atomSize //increment ptr
	//if these match, then our who string was uint32 sized
	if whoIncrement < whoLength {
		//otherwise, pad it out to the next increment
		whoIncrement += atomSize
	}

	return whoIncrement
}

func (acl *Nfs4_acl) SetWrite() () {
	for _, ace := range acl.ace_list {
		ace.access_mask = ace.access_mask | NFS4_ACE_WRITE_DATA
	}
}

func (acl *Nfs4_acl) ClearWrite() () {
	for _, ace := range acl.ace_list {
		ace.access_mask = ace.access_mask &^ NFS4_ACE_WRITE_DATA
	}
}
