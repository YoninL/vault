package alibaba

import (
	"context"
	"fmt"
	"time"

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

	displayName := req.DisplayName
	userUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}
	userName := fmt.Sprintf("vault-%s-%s-%s-%data", userGroupName, displayName, userUUID, time.Now().Unix())

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
