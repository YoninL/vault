package alibaba

import (
	"context"
	"fmt"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const secretType = "access_key"

func secretAccessKeys(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretType,
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access Key",
			},

			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret Key",
			},
		},

		Renew:  b.secretAccessKeysRenew,
		Revoke: secretAccessKeysRevoke,
	}
}

func (b *backend) secretAccessKeysRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	userGroupName := data.Get("user_group_name").(string)

	resp := &logical.Response{Secret: req.Secret}

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

func secretAccessKeysRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}
	userName, ok := usernameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing username internal data")
	}

	userGroupNameRaw, ok := req.Secret.InternalData["user_group_name"]
	if !ok {
		return nil, fmt.Errorf("secret is missing user_group_name internal data")
	}
	userGroupName, ok := userGroupNameRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing user_group_name internal data")
	}

	accessKeyIDRaw, ok := req.Secret.InternalData["access_key_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing access_key_id internal data")
	}
	accessKeyID, ok := accessKeyIDRaw.(string)
	if !ok {
		return nil, fmt.Errorf("secret is missing access_key_id internal data")
	}

	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client, err := ramClient(creds.AccessKey, creds.SecretKey)
	if err != nil {
		return nil, err
	}

	// Do the opposite of all this.
	// TODO can I skip deleting the access key and removing the user from the group
	// if I just delete the user?
	accessKeyReq := ram.CreateDeleteAccessKeyRequest()
	accessKeyReq.UserAccessKeyId = accessKeyID
	if _, err := client.DeleteAccessKey(accessKeyReq); err != nil {
		return nil, err
	}

	removeUserReq := ram.CreateRemoveUserFromGroupRequest()
	removeUserReq.UserName = userName
	removeUserReq.GroupName = userGroupName
	if _, err := client.RemoveUserFromGroup(removeUserReq); err != nil {
		return nil, err
	}

	deleteUserReq := ram.CreateDeleteUserRequest()
	deleteUserReq.UserName = userName
	if _, err := client.DeleteUser(deleteUserReq); err != nil {
		return nil, err
	}

	return nil, nil
}
