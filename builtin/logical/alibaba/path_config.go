package alibaba

import (
	"context"

	"github.com/go-errors/errors"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"access_key": {
				Type:        framework.TypeString,
				Description: "Access key with permission to create new keys.",
			},
			"secret_key": {
				Type:        framework.TypeString,
				Description: "Secret key with permission to create new keys.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			// There's no update operation because you would never need to update a secret_key
			// without also needing to update the access_key, thus replacing the entire config.
			// So, each time you need to change the config you need to create an entirely new one.
			logical.CreateOperation: operationConfigCreate,
			logical.ReadOperation:   operationConfigRead,
			logical.DeleteOperation: operationConfigDelete,
		},
		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func operationConfigCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessKey := ""
	if accessKeyIfc, ok := data.GetOk("access_key"); ok {
		accessKey = accessKeyIfc.(string)
	} else {
		return nil, errors.New("access_key is required")
	}
	secretKey := ""
	if secretKeyIfc, ok := data.GetOk("secret_key"); ok {
		secretKey = secretKeyIfc.(string)
	} else {
		return nil, errors.New("secret_key is required")
	}
	entry, err := logical.StorageEntryJSON("config", credConfig{
		AccessKey: accessKey,
		SecretKey: secretKey,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func operationConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	creds, err := readCredentials(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, nil
	}

	// NOTE:
	// "secret_key" is intentionally not returned by this endpoint,
	// as we lean away from returning sensitive information unless it's absolutely necessary.
	return &logical.Response{
		Data: map[string]interface{}{
			"access_key": creds.AccessKey,
		},
	}, nil
}

func operationConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, err
	}
	return nil, nil
}

func readCredentials(ctx context.Context, s logical.Storage) (*credConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	creds := &credConfig{}
	if err := entry.DecodeJSON(creds); err != nil {
		return nil, err
	}
	return creds, nil
}

type credConfig struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

const pathConfigRootHelpSyn = `
Configure the root credConfig that are used to manage RAM.
`

const pathConfigRootHelpDesc = `
Before doing anything, the AliCloud backend needs credConfig that are able
to manage RAM policies, users, access keys, etc. This endpoint is used
to configure those credConfig. They don't necessarily need to be root
keys as long as they have permission to manage RAM.
`
