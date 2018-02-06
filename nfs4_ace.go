package nfs4acl

import (
	"bytes"
	"fmt"
)

//Static Functions
func AceGetWhoType(who string) uint {
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

func AceWhoStringAtomLength(whoLength int) int {
	//since the Who string isn't necessarily uint32 sized
	//we need to find out how many uint32's, rounding up, it used
	//so we can properly increment the pointer
	// get the size of our Who string, rounded down to the nears atom
	whoIncrement := int(whoLength/ATOM_SIZE) * ATOM_SIZE //increment ptr
	//if these match, then our Who string was uint32 sized
	if whoIncrement < whoLength {
		//otherwise, pad it out to the next increment
		whoIncrement += ATOM_SIZE
	}

	return whoIncrement
}

//Struct Declaration

type NFS4ACE struct {
	AceType    uint32
	WhoType    uint
	Who        string
	Flags      uint32
	AccessMask uint32
}

//NFS4ACE struct constructor
func NewNFS4ACE(aceType, flag, mask uint32, who string) *NFS4ACE {
	return &NFS4ACE{
		AceType:    aceType,
		Who:        who,
		WhoType:    AceGetWhoType(who),
		Flags:      flag,
		AccessMask: mask,
	}
}

//Ace methods

//Prints the Ace
func (ace *NFS4ACE) PrintACE(verbose, isDir bool) error {
	//Create print buffer
	var buffer bytes.Buffer

	//Prepare Ace Type
	if verbose {
		switch ace.AceType {
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
		switch ace.AceType {
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
	if ace.Flags&NFS4_ACE_FILE_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_FILE_INHERIT)
	}
	if ace.Flags&NFS4_ACE_DIRECTORY_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_DIR_INHERIT)
	}
	if ace.Flags&NFS4_ACE_NO_PROPAGATE_INHERIT_ACE != 0 {
		buffer.WriteRune(FLAG_NO_PROPAGATE_INHERIT)
	}
	if ace.Flags&NFS4_ACE_INHERIT_ONLY_ACE != 0 {
		buffer.WriteRune(FLAG_INHERIT_ONLY)
	}
	if ace.Flags&NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG != 0 {
		buffer.WriteRune(FLAG_SUCCESSFUL_ACCESS)
	}
	if ace.Flags&NFS4_ACE_FAILED_ACCESS_ACE_FLAG != 0 {
		buffer.WriteRune(FLAG_FAILED_ACCESS)
	}
	if ace.Flags&NFS4_ACE_IDENTIFIER_GROUP != 0 {
		buffer.WriteRune(FLAG_GROUP)
	}
	if ace.Flags&NFS4_ACE_OWNER != 0 {
		buffer.WriteRune(FLAG_OWNER_AT)
	}
	if ace.Flags&NFS4_ACE_GROUP != 0 {
		buffer.WriteRune(FLAG_GROUP_AT)
	}
	if ace.Flags&NFS4_ACE_EVERYONE != 0 {
		buffer.WriteRune(FLAG_EVERYONE_AT)
	}
	buffer.WriteRune(':')

	//Prepare Ace WHO
	buffer.WriteString(ace.Who)
	buffer.WriteRune(':')

	//Prepare Ace Mask
	if isDir {
		if ace.AccessMask&NFS4_ACE_LIST_DIRECTORY != 0 {
			buffer.WriteRune(PERM_LIST_DIR)
		}
		if ace.AccessMask&NFS4_ACE_ADD_FILE != 0 {
			buffer.WriteRune(PERM_CREATE_FILE)
		}
		if ace.AccessMask&NFS4_ACE_ADD_SUBDIRECTORY != 0 {
			buffer.WriteRune(PERM_CREATE_SUBDIR)
		}
		if ace.AccessMask&NFS4_ACE_DELETE_CHILD != 0 {
			buffer.WriteRune(PERM_DELETE_CHILD)
		}
	} else {
		if ace.AccessMask&NFS4_ACE_READ_DATA != 0 {
			buffer.WriteRune(PERM_READ_DATA)
		}
		if ace.AccessMask&NFS4_ACE_WRITE_DATA != 0 {
			buffer.WriteRune(PERM_WRITE_DATA)
		}
		if ace.AccessMask&NFS4_ACE_APPEND_DATA != 0 {
			buffer.WriteRune(PERM_APPEND_DATA)
		}
	}
	if ace.AccessMask&NFS4_ACE_DELETE != 0 {
		buffer.WriteRune(PERM_DELETE)
	}
	if ace.AccessMask&NFS4_ACE_EXECUTE != 0 {
		buffer.WriteRune(PERM_EXECUTE)
	}
	if ace.AccessMask&NFS4_ACE_READ_ATTRIBUTES != 0 {
		buffer.WriteRune(PERM_READ_ATTR)
	}
	if ace.AccessMask&NFS4_ACE_WRITE_ATTRIBUTES != 0 {
		buffer.WriteRune(PERM_WRITE_ATTR)
	}
	if ace.AccessMask&NFS4_ACE_READ_NAMED_ATTRS != 0 {
		buffer.WriteRune(PERM_READ_NAMED_ATTR)
	}
	if ace.AccessMask&NFS4_ACE_WRITE_NAMED_ATTRS != 0 {
		buffer.WriteRune(PERM_WRITE_NAMED_ATTR)
	}
	if ace.AccessMask&NFS4_ACE_READ_ACL != 0 {
		buffer.WriteRune(PERM_READ_ACL)
	}
	if ace.AccessMask&NFS4_ACE_WRITE_ACL != 0 {
		buffer.WriteRune(PERM_WRITE_ACL)
	}
	if ace.AccessMask&NFS4_ACE_WRITE_OWNER != 0 {
		buffer.WriteRune(PERM_WRITE_OWNER)
	}
	if ace.AccessMask&NFS4_ACE_SYNCHRONIZE != 0 {
		buffer.WriteRune(PERM_SYNCHRONIZE)
	}

	fmt.Println(buffer.String())
	return nil
}

//Bitwise ORs the access mask. This will set any bits in the specified access mask
//but will not modify any existing set bits
// value    = 00110101
// mask     | 00000011
// result     00110111
func (ace *NFS4ACE) applyAccessMask(accessMask uint32) {
	ace.AccessMask = ace.AccessMask | accessMask
}

//Bitwise AND NOT the access mask (bit clear). This will unset any bits in the specified access mask
//but will not modify any others
// value    = 00110101  mask = 00000011
// NOT MASK & 11111100
// result     00110100
func (ace *NFS4ACE) removeAccessMask(accessMask uint32) {
	ace.AccessMask = ace.AccessMask &^ accessMask
}

//Sets the accessmask to the specified mask. Total overwrite
func (ace *NFS4ACE) setAccessMask(accessMask uint32) {
	ace.AccessMask = accessMask
}


//Bitwise ORs the flags. This will set any bits in the specified flags
//but will not modify any existing set bits
func (ace *NFS4ACE) applyFlags(flags uint32) {
	ace.Flags = ace.Flags | flags
}

//Bitwise AND NOT the flags (bit clear). This will unset any bits in the specified flags
//but will not modify any others
func (ace *NFS4ACE) removeFlags(flags uint32) {
	ace.Flags = ace.Flags &^ flags
}

//Sets the flags to the specified mask. Total overwrite
func (ace *NFS4ACE) setFlags(flags uint32) {
	ace.Flags = flags
}
