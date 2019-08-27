package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib
	"crypto/rsa"

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported

func has(hashdata []byte) []byte {
	h := userlib.NewSHA256()
	h.Write(hashdata)
	ha := h.Sum(nil)
	return ha
}

type user struct {
	username   string
	password   string
	file       map[string]filemetadata
	privatekey rsa.PrivateKey
	publickey  rsa.PublicKey
	mackey     []byte
}

func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	password   string
	file       map[string]filemetadata
	privatekey rsa.PrivateKey
	publickey  rsa.PublicKey
	mackey     []byte
	Username   string
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
}

// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
// func (userdata *User) AppendFile(filename string, data []byte) (err error) {
// 	return
// }

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.

// func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
// 	return
// }

// ShareFile : Function used to the share file with other user
// func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
// 	return
// }

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender

// func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
// 	return
// }

// RevokeFile : function used revoke the shared file access
// func (userdata *User) RevokeFile(filename string) (err error) {
// 	return
// }

//helper function to CFBEncrypter
func newCFBEncrypter(plainText []byte, key []byte) (ciphertext []byte) {
	ciphertext = make([]byte, userlib.BlockSize+len(plainText))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], plainText)
	return
}

func newCFBDecrypter(ciphertext []byte, Key []byte) (plaintext []byte, err error) {
	if len(ciphertext) <= userlib.BlockSize {
		return nil, errors.New(strings.ToTitle("Invalid Ciphertext"))
	}
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(Key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	plaintext = ciphertext[userlib.BlockSize:]
	return plaintext, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	var user User
	rsaKEY, err := userlib.GenerateRSAKey()
	if err != nil {
		return nil, err
	}
	user.Username = username
	user.password = password

	if user.Username == "" || user.password == "" {
		err = errors.New("bad")
		return nil, err
	}

	user.file = make(map[string]filemetadata)
	user.privatekey = *rsaKEY
	user.publickey = rsaKEY.PublicKey
	key := userlib.Argon2Key([]byte(user.password), []byte(user.Username), 16)
	userstr, _ := json.Marshal(user)
	userlib.KeystoreSet(user.Username, user.publickey)

	var hmac MAC
	hmac.ciphertext = newCFBEncrypter([]byte(userstr), key)
	hmac.mac = hmac.ciphertext

	userData, _ := json.Marshal(hmac)
	userKey := has([]byte(user.Username + user.password))
	EuserData := newCFBEncrypter(userData, key)
	userlib.DatastoreSet(string(userKey), EuserData)
	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

// GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	var user User
	userKey := has([]byte(username + password))
	value, ok := userlib.DatastoreGet(string(userKey))
	if ok == false || value == nil {
		err = errors.New("data corrupted")
		return nil, err
	}

	key := userlib.Argon2Key([]byte(password), has([]byte(username)), 16)
	userdata, err := newCFBDecrypter(value, key)
	if err != nil {
		return nil, err
	}
	var emac MAC
	json.Unmarshal(userdata, emac)
	retmac := has(emac.ciphertext)
	res := userlib.Equal(emac.mac, retmac)
	if res == false {
		return nil, errors.New("corrupted data")
	}
	ciphertext, _ := newCFBDecrypter(emac.ciphertext, key)
	json.Unmarshal(ciphertext, user)
	return &user, nil

}