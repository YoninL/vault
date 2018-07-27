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

	/*
		The most important thing for us to delete is the access key, as it's what
		we've shared with the caller to use as credentials, so let's do that first.
	*/
	accessKeyReq := ram.CreateDeleteAccessKeyRequest()
	accessKeyReq.UserAccessKeyId = accessKeyID
	accessKeyReq.UserName = userName
	if _, err := client.DeleteAccessKey(accessKeyReq); err != nil {
		return nil, err
	}

	/*
		Now let's back that user out of the user group.
	*/
	removeUserReq := ram.CreateRemoveUserFromGroupRequest()
	removeUserReq.UserName = userName
	removeUserReq.GroupName = userGroupName
	if _, err := client.RemoveUserFromGroup(removeUserReq); err != nil {
		return nil, err
	}

	/*
		At this point, deleting the user SHOULD succeed but an important caveat
		is that if somebody, out-of-band from Vault, added policies to them,
		added them to another user group, added an MFA device, or associated
		ANYTHING else to them, this will fail. We don't try to hunt down and
		delete every possible thing you can associate with a user in Alibaba,
		because that list will change over time, and it would also add a bunch
		of latency to this code.
	*/
	deleteUserReq := ram.CreateDeleteUserRequest()
	deleteUserReq.UserName = userName
	if _, err := client.DeleteUser(deleteUserReq); err != nil {
		return nil, err
	}

	return nil, nil
}
