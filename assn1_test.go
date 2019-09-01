package assn1

import (
	//1

	"fmt"
	"testing"

	"github.com/sarkarbidya/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Error("Initialized invalid user", err1)
	}

	// add more test cases here
}

func TestUserStorage(t *testing.T) {
	InitUser("kuldeep", "kuldeep")
	u1, err1 := GetUser("kuldeep", "kuldeep")
	if err1 == nil && u1.Username == "kuldeep" {
		fmt.Printf("User name is %s", u1.Username)
		//t.Log("Cannot load data for invalid user", u1)
	} else {
		fmt.Printf("Error is :%v\n", err1)
		t.Error("Data loaded for invalid user", err1)
	}
	//add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	InitUser("kuldeep", "kuldeep")
	u1, _ := GetUser("kuldeep", "kuldeep")
	_ = u1.StoreFile("file1", data1)

}

// /*
// func TestFileShareReceive(t *testing.T) {
//   // add test cases here
// }
// */
