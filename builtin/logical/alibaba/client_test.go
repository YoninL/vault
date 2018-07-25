package alibaba

import (
	"fmt"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

func TestHowDoPoliciesWork(t *testing.T) {
	key := ""
	secret := ""
	client, err := ramClient(key, secret)
	if err != nil {
		panic(err)
	}

	getUserReq := ram.CreateGetUserRequest()
	getUserReq.UserName = "jeff-mitchell"
	userResp, err := client.GetUser(getUserReq)
	if err != nil {
		panic(err)
	}

	listPoliciesReq := ram.CreateListPoliciesForUserRequest()
	listPoliciesReq.UserName = userResp.User.UserName
	policiesResp, err := client.ListPoliciesForUser(listPoliciesReq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("starting with these policies: %s\n", policiesResp.Policies.Policy)

	attachReq := ram.CreateAttachPolicyToUserRequest()
	attachReq.UserName = userResp.User.UserName
	attachReq.PolicyName = "AliyunMQPubOnlyAccess"
	attachReq.PolicyType = "System"
	attachResp, err := client.AttachPolicyToUser(attachReq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("attach response: %+v\n", attachResp)

	policiesResp, err = client.ListPoliciesForUser(listPoliciesReq)
	if err != nil {
		panic(err)
	}
	fmt.Printf("now have these policies: %s\n", policiesResp.Policies.Policy)

	// Try to add policies to him other ways
	// After each step list his policies
	// And make sure you say what way you're attaching them each time
}

/*
Here's a totally random policy to test with:
{
	"AttachmentCount": 0,
	"Description": "消息队列(MQ)的发布权限",
	"PolicyName": "AliyunMQPubOnlyAccess",
	"UpdateDate": "2017-08-14T06:40:16Z",
	"CreateDate": "2017-08-11T09:00:12Z",
	"DefaultVersion": "v2",
	"PolicyType": "System"
}
*/

/*
Getting a policy is just like this, so there's no policy arn that I can see, we do all this with names AND types basically.
You do have to have the type so that's how you would configure a policy, and then we'd actually get it on the fly.
Are the types evident in the UI? Yep. :-)
{
	"Policy": {
		"AttachmentCount": 0,
		"Description": "消息队列(MQ)的发布权限",
		"PolicyName": "AliyunMQPubOnlyAccess",
		"UpdateDate": "2017-08-14T06:40:16Z",
		"CreateDate": "2017-08-11T09:00:12Z",
		"DefaultVersion": "v2",
		"PolicyType": "System"
	},
	"RequestId": "530EDCC7-79A7-48B4-A8F6-C9204AABB273"
}
*/

/*
Let's test on Jeff and try adding policies to him in various ways and seeing how they turn out. Attaching them too.
{
	"Comments": "",
	"UserName": "jeff-mitchell",
	"UpdateDate": "2018-06-06T23:42:31Z",
	"UserId": "263756828328551814",
	"DisplayName": "jeff-mitchell",
	"CreateDate": "2018-06-06T23:42:31Z"
}
*/
