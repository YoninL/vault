package alibaba

import (
	"context"

	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathCreds(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("user_group_name"),
		Fields: map[string]*framework.FieldSchema{
			"user_group_name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsRead,
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userGroupName := data.Get("user_group_name").(string)

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client, err := ramClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	userName, err := generateUsername(req.DisplayName, userGroupName)
	if err != nil {
		return nil, err
	}

	// TODO do I need to do some weird rollback shiznit in case some middle step fails?
	createUserReq := ram.CreateCreateUserRequest()
	createUserReq.UserName = userName
	createUserReq.DisplayName = userName
	if _, err := client.CreateUser(createUserReq); err != nil {
		return nil, err
	}

	addUserReq := ram.CreateAddUserToGroupRequest()
	addUserReq.UserName = userName
	addUserReq.GroupName = userGroupName
	if _, err := client.AddUserToGroup(addUserReq); err != nil {
		return nil, err
	}

	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	accessKeyResp, err := client.CreateAccessKey(accessKeyReq)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(secretType).Response(map[string]interface{}{
		"access_key": accessKeyResp.AccessKey.AccessKeyId,
		"secret_key": accessKeyResp.AccessKey.AccessKeySecret,
	}, map[string]interface{}{
		"username":        userName,
		"user_group_name": userGroupName,
		"access_key_id":   accessKeyResp.AccessKey.AccessKeyId,
	})

	role, err := readRole(ctx, req.Storage, userGroupName)
	if err != nil {
		return nil, err
	}
	if role.TTL != 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL != 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}

// TODO test coverage
// Normally we'd do something like this to create a username:
// fmt.Sprintf("vault-%s-%s-%s-%d", userGroupName, displayName, userUUID, time.Now().Unix())
// However, Alibaba limits the username length to 1-64, so we have to make some sacrifices.
func generateUsername(displayName, userGroupName string) (string, error) {
	// Limit set by Alibaba API.
	maxLength := 64

	// This reserves the length it would take to have a dash in front of the UUID
	// for readability, and 5 significant base64 characters, which provides 1,073,741,824
	// possible random combinations.
	lenReservedForUUID := 6

	userName := userGroupName
	if displayName != "" {
		userName += "-" + displayName
	}

	// However long our username is so far with valuable human-readable naming
	// conventions, we need to include at least part of a UUID on the end to minimize
	// the risk of naming collisions.
	if maxLength-len(userName) > lenReservedForUUID {
		userName = userName[:maxLength-lenReservedForUUID]
	}

	uid, err := uuid.GenerateUUID()
	if err != nil {
		return "", err
	}
	shortenedUUID := strings.Replace(uid, "-", "", -1)

	userName += "-" + shortenedUUID
	if len(userName) > maxLength {
		// Slice off the excess UUID, bringing UUID length down to possibly only
		// 5 significant characters.
		return userName[:maxLength], nil
	}
	return userName, nil
}

// TODO update this stuff
const pathCredsHelpSyn = `
Generate an access key pair for a specific role.
`

const pathCredsHelpDesc = `
This path will generate a new, never before used key pair for
accessing AWS. The IAM policy used to back this key pair will be
the "user_group_name" parameter. For example, if this backend is mounted at "aws",
then "aws/creds/deploy" would generate access keys for the "deploy" role.

The access keys will have a lease associated with them. The access keys
can be revoked by using the lease ID.
`
