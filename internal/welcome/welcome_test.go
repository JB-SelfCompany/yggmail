package welcome

import (
	"fmt"
	"testing"
)

func Test_WelcomeGenerate(t *testing.T) {
	newUser := "Tristan"

	// generate welcome message header
	bytesOut, e := welcomeMessageFor(newUser)

	if e != nil {
		t.Fail()
	} else if len(bytesOut) == 0 {
		t.Fail()
	}

	fmt.Printf("Out: %v\n", bytesOut)
}
