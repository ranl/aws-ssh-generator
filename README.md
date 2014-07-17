aws-ssh-generator
=================

Generate ssh_config file from Amazon EC2

__aws.json__
```json
{
    "defaults": {
        "alias": "{account}-{tags[Name]}",
        "ssh_opts": {
            "ServerAliveInterval": 60,
            "IdentityFile": "/home/foo/id_rsa",
            "User": "root",
            "Port": 22
        }
    },
    "credentials": {
        "company_a": {
            "key": "AAAAAAAAAAAAAAAA",
            "secret": "bbbbbbbbbbbbbbbbbbbbbb",
            "targets": [
                {
                    "type": "none",
                    "ssh_opts": {
                        "IdentityFile": "/home/foo/.ssh/my_priv.pem",
                        "StrictHostKeyChecking": "no"
                    }
                }
            ]
        },
        "company_b": {
            "key": "cccccccccccc",
            "secret": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
            "targets": [
                {
                    "type": "tag",
                    "value": "prod",
                    "name": "env",
                    "alias": "{account}-{tags[env]}-{tags[Name]}",
                    "ssh_opts": {
                        "IdentityFile": "/home/foo/.ssh/id_rsa-prod",
                        "Port": 22
                    }
                },
                {
                    "type": "tag",
                    "value": "test",
                    "name": "env",
                    "alias": "{account}-{tags[env]}-{tags[Name]}",
                    "ssh_opts": {
                        "IdentityFile": "/home/foo/.ssh/id_rsa-qa"
                    }
                }
            ]
        }
    }
}
```

each entry under the `credentials` section represents an AWS account.

for example `company_a` uses `key` as the amazon user key and `secret` as amazon user secret.
`targets` is a list of settings to match a specific hosts of that account, 
if the check will result as true the settings will be used in ssh_config.

all the ssh configuration are supported in `ssh_opts` dict

`alias` will be used as the `Host` value, for easy bash-completion

all the settings under `defaults` will be appended to each host if not specified in the target
or no target is found

__Alias Format__
```json
{
    "account": "account name",
    "tags": {all ec2 tags},
    "id": "instance id",
    "public_dns": "public ip",
    "private_dns": "private ip",
    "keypair": "key pair name",
}
```

__Checks Types__

* none: no checks will be made
```json
{
    "type": "none"
}
```

* tag: if the instance has the tag `name: value` in it's ec2 meta data
```json
{
    "type": "tag",
    "value": "test",
    "name": "env"
}
```

__Setup Example__
```
0 * * * * aws_ssh_generator.py ~/aws.json > ~/.ssh/config.new && mv ~/.ssh/config.new ~/.ssh/config
```
