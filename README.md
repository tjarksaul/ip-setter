# ip-setter
Go script to set IP address for misc stuff. All parameters can be send via GET or POST request.

## Set IP address
This action can be performed at `/` with the following parameters:
Parameter|Description
_________|___________
`user`|User name of the user to set the IP
`password`|Password of that user

## Create user
This action can be performed at `/create` with the following parameters:
Parameter|Description
_________|___________
`user`|User name of the new user
`password`|Password of that user

## Managing users
This actions can be performed at `/manage`.
Parameter|Description
_________|___________
`action`|The action to perform, currently only `setPrivileges`

### Changing user's privileges
A users permission can be changed with `action=setPrivileges` and the following parameters:
Parameter|Description
_________|___________
`user`|User name of the administrator
`password`|Password of that user
`changeUser`|User name of the user whose privileges are to be changed
`privileges`|A positive integer. >=1 can set IP addresses, >=2 is an administrator
