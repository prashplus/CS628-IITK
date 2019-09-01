package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.
//
import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

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

	// And a random RSA argonkey.  In this case, ignoring the error
	// return value
	var argonkey *userlib.PrivateKey
	argonkey, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", argonkey)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

//euser helper struct to store encrypted_data and mac(encrypted_data)
type euser struct {
	CipherText []byte
	Mac        []byte
}

//User : User structure used to store the user information
type User struct {
	Username   string
	pass       string
	files      map[string]Metadata
	sharedfile map[string]sharingRecord
	PrivateKey *userlib.PrivateKey
}

//Metadata struct
type Metadata struct {
	fileName  string
	key       []byte
	fblocks   map[int]string
	fblockmac map[int][]byte
	size      int
}

//FileBlock Struct
type FileBlock struct {
	Data []byte
	Hmac []byte
}

// // This creates a sharing record, which is a argonkey pointing to something
// // in the datastore to share with the recipient.

// // This enables the recipient to access the encrypted file as well
// // for reading/appending.

// // Note that neither the recipient NOR the datastore should gain any
// // information about what the sender calls the file.  Only the
// // recipient can access the sharing record, and only the recipient
// // should be able to know the sender.
// // You may want to define what you actually want to pass as a
// // sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	var mdata Metadata
}

//Hash func to hash as []byte
func Hash(datatoHash []byte) []byte {
	hasher := userlib.NewSHA256()
	hasher.Write(datatoHash)
	hash := hasher.Sum(nil)
	return hash
}

//encrypt loadfile,helper function to CFBEncrypter
func encrypt(plainText []byte, argonkey []byte) (ciphertext []byte) {
	ciphertext = make([]byte, userlib.BlockSize+len(plainText))
	iv := ciphertext[:userlib.BlockSize]
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(argonkey, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], plainText)
	return
}

//decrypt helper function to CFBDecrypter
func decrypt(ciphertext []byte, Key []byte) (plaintext []byte, err error) {
	if len(ciphertext) <= userlib.BlockSize {
		return nil, errors.New(strings.ToTitle("Invalid Ciphertext"))
	}
	iv := ciphertext[:userlib.BlockSize]
	cipher := userlib.CFBDecrypter(Key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], ciphertext[userlib.BlockSize:])
	plaintext = ciphertext[userlib.BlockSize:]
	return plaintext, nil
}

//function to store blocks
func storeBlock(filename string, data []byte, offset int, argonkey []byte) string {
	addr := string(Hash([]byte(filename + string(offset))))
	Edata := encrypt(data, argonkey)
	userlib.DatastoreSet(addr, Edata)
	return addr

}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public argonkey in the keystore.

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
	var userEmac euser
	user.Username = username
	user.pass = password
	rsaKey, err := userlib.GenerateRSAKey()

	if user.Username == "" || user.pass == "" {
		err = errors.New("Invalid Username or Password")
		return nil, err
	}
	argonkey := userlib.Argon2Key([]byte(user.pass), []byte(user.Username), 16)
	pubkey := rsaKey.PublicKey
	userlib.KeystoreSet(user.Username, pubkey)

	userstructMarshal, _ := json.Marshal(user)

	userEmac.CipherText = encrypt([]byte(userstructMarshal), argonkey)

	hasher := userlib.NewSHA256()
	hasher.Write(userEmac.CipherText)
	userEmac.Mac = hasher.Sum(nil)

	user.files = make(map[string]Metadata)
	user.sharedfile = make(map[string]sharingRecord)

	user.PrivateKey = rsaKey

	userData, _ := json.Marshal(userEmac)

	hasher = userlib.NewSHA256()
	hasher.Write([]byte(user.Username + user.pass))
	keyToDataStore := hasher.Sum(nil)

	encryptedUserData := encrypt(userData, argonkey)
	userlib.DatastoreSet(string(keyToDataStore), encryptedUserData)

	return &user, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
// GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	//Generating Argon key
	argonkey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	hasher := userlib.NewSHA256()
	hasher.Write([]byte(username + password))
	keyToDataStore := hasher.Sum(nil)

	value, ok := userlib.DatastoreGet(string(keyToDataStore))

	if value == nil || ok == false {
		return nil, errors.New("Data Corrupted")
	}
	userData, err := decrypt(value, argonkey)
	if err != nil {
		return nil, errors.New("Data Corrupted")
	}
	var emac euser
	json.Unmarshal(userData, &emac)

	hasher = userlib.NewSHA256()
	hasher.Write([]byte(emac.CipherText))
	returnedMAC := hasher.Sum(nil)

	ok1 := userlib.Equal(emac.Mac, returnedMAC)
	if ok1 == false {
		return nil, errors.New("Data Corrupted")
	}
	var user User
	plaintext, _ := decrypt(emac.CipherText, argonkey)
	json.Unmarshal(plaintext, &user)

	return &user, nil
}

// StoreFile : function used to create a  file
// It should store the file in fblocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	var filedata Metadata
	var block FileBlock

	key := userlib.Argon2Key([]byte(userdata.pass), Hash([]byte(userdata.Username)), 16)

	if filename == "" || len(data)%configBlockSize != 0 {
		return errors.New("Error in Storing file")
	}

	filedata.fileName = filename
	filedata.size = len(data) / configBlockSize
	filedata.fblockmac = make(map[int][]byte)
	filedata.fblocks = make(map[int]string)
	filedata.key = userlib.Argon2Key([]byte(userdata.pass), []byte(filename), 16)

	for i := 0; i < filedata.size; i++ {
		filedata.fblockmac[i] = Hash(data[i : configBlockSize+i])
		filedata.fblocks[i] = storeBlock(filename, data[i:configBlockSize+i], i, filedata.key)
	}
	userdata.files[filename] = filedata
	userStr, _ := json.Marshal(userdata)
	block.Data = encrypt([]byte(userStr), key)
	block.Hmac = Hash(block.Data)
	storedata(*userdata, block)
	return

}

//storeData fuction
func storedata(user User, block FileBlock) {
	userData, _ := json.Marshal(block)
	userKey := Hash([]byte(user.Username + user.pass))
	key := userlib.Argon2Key([]byte(user.pass), Hash([]byte(user.Username)), 16)
	EuserData := encrypt(userData, key)
	userlib.DatastoreSet(string(userKey), EuserData)
}

// AppendFile Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	argonkeynew := userlib.Argon2Key([]byte(userdata.pass), Hash([]byte(userdata.Username)), 16)
	var eusr euser
	j := 0

	if len(data)%configBlockSize != 0 || filename == "" || len(data) == 0 {
		e := errors.New("Either filename not valid or length mismatch")
		return e
	}

	mData := userdata.files[filename]
	if mData.fileName != filename {
		return errors.New("File not found")
	}

	for i := mData.size; i < mData.size+(len(data)/configBlockSize); i++ {
		mData.fblocks[i] = storeBlock(filename, data[j:j+configBlockSize], i, mData.key)
		mData.fblockmac[i] = Hash(data[j : j+configBlockSize])
		j += configBlockSize
	}

	//UPDATE META DATA SIZE
	mData.size += len(data) / configBlockSize
	userdata.files[filename] = mData
	userdatastruct, _ := json.Marshal(userdata)
	eusr.CipherText = encrypt([]byte(userdatastruct), argonkeynew)
	eusr.Mac = Hash(eusr.CipherText)

	userData, _ := json.Marshal(eusr)
	ukey := Hash([]byte(userdata.Username + userdata.pass))
	EncUserData := encrypt([]byte(userData), argonkeynew)
	userlib.DatastoreSet(string(ukey), EncUserData)

	return nil
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) fblocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {
	if filename == "" {
		return nil, errors.New("Empty file name")
	}
	mdata := userdata.files[filename]
	add := mdata.fblocks[offset]

	if mdata.size <= offset {
		return nil, errors.New("Offset not found")
	}

	loadfile, e1 := userlib.DatastoreGet(add)
	if e1 != true {
		return nil, errors.New("Data not found")
	}

	data, err = decrypt(loadfile, mdata.key)
	if err != nil {
		return nil, errors.New("Cannot decrypt(corrupted)")
	}

	hash := userlib.NewSHA256()
	hash.Write(data)
	hashed := hash.Sum(nil)

	checkingHash := userlib.Equal(mdata.fblockmac[offset], hashed)
	if checkingHash != true {
		return nil, errors.New("Mac not matched")
	}

	return
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	if filename == "" || recipient == "" {
		return "", errors.New("Either Filename or Recipient is empty")
	}
	pk, check := userlib.KeystoreGet(recipient)

	if !check {
		return "", errors.New("Recipient Not found")
	}


	return
}

// ReceiveFile :Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
//ReceiveFile : function used to receive the file details from the sender
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	if filename == "" || sender == "" {
		return errors.New("Either filename or sender is empty")
	}

	
	return errors.New("err")
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {
	if filedata == "" {
		return errors.New("Filename is empty")
	}
	return
}
