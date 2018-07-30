package util

import (
	"strings"
	"testing"
)

func TestGenUsernameDisplaynameAndUsergroupname(t *testing.T) {
	displayName := "displayName"
	userGroupName := "userGroupName"

	// example of an expected result:
	// userGroupName-displayName-db60aa6b7ddbd7cd8e90c4faa3abff98
	username, err := GenerateUsername(displayName, userGroupName)
	if err != nil {
		t.Fatal(err)
	}
	if len(username) > maxLength {
		t.Fatalf("length of %s is %d, which is greater than the max length", username, len(username))
	}
	expectedPrefix := userGroupName + "-" + displayName + "-"
	if !strings.HasPrefix(username, expectedPrefix) {
		t.Fatalf("%s doesn't start with expected prefix of %s", username, expectedPrefix)
	}
	fields := strings.Split(username, "-")
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields but received %d", len(fields))
	}
}

func TestGenUsernameUsergroupname(t *testing.T) {
	displayName := ""
	userGroupName := "userGroupName"

	// example of an expected result:
	// userGroupName-0669a86fbf4b2c0111e29faeacc7ce3c
	username, err := GenerateUsername(displayName, userGroupName)
	if err != nil {
		t.Fatal(err)
	}
	if len(username) > maxLength {
		t.Fatalf("length of %s is %d, which is greater than the max length", username, len(username))
	}
	expectedPrefix := userGroupName + "-"
	if !strings.HasPrefix(username, expectedPrefix) {
		t.Fatalf("%s doesn't start with expected prefix of %s", username, expectedPrefix)
	}
	fields := strings.Split(username, "-")
	if len(fields) != 2 {
		t.Fatalf("expected 3 fields but received %d", len(fields))
	}
}

func TestGenUsernameFieldsReallyLong(t *testing.T) {
	displayName := "displayNamedisplayNamedisplayName"
	userGroupName := "userGroupNameuserGroupNameuserGroupName"

	// example of an expected result:
	// userGroupNameuserGroupNameuserGroupName-displayNamedisplay-e8dbe
	username, err := GenerateUsername(displayName, userGroupName)
	if err != nil {
		t.Fatal(err)
	}
	if len(username) > maxLength {
		t.Fatalf("length of %s is %d, which is greater than the max length", username, len(username))
	}
	expectedPrefix := userGroupName + "-"
	if !strings.HasPrefix(username, expectedPrefix) {
		t.Fatalf("%s doesn't start with expected prefix of %s", username, expectedPrefix)
	}
	fields := strings.Split(username, "-")
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields but received %d", len(fields))
	}
}

func TestGenUsernameFieldsReallyShort(t *testing.T) {
	displayName := "d"
	userGroupName := "u"

	// example of an expected result:
	// u-d-e10aeb204a886cf414b25e900f6b4419
	username, err := GenerateUsername(displayName, userGroupName)
	if err != nil {
		t.Fatal(err)
	}
	if len(username) > maxLength {
		t.Fatalf("length of %s is %d, which is greater than the max length", username, len(username))
	}
	expectedPrefix := userGroupName + "-"
	if !strings.HasPrefix(username, expectedPrefix) {
		t.Fatalf("%s doesn't start with expected prefix of %s", username, expectedPrefix)
	}
	fields := strings.Split(username, "-")
	if len(fields) != 3 {
		t.Fatalf("expected 3 fields but received %d", len(fields))
	}
}
