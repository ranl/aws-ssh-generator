#!/usr/bin/env python

'''
Generate SSH config file file Amazon EC2 Instances
'''

# Python Libs
import sys
import logging
import json

# Third party libs
import boto.ec2
import boto

# Globals
log = logging.getLogger(__name__)
private_entry = '''Host vpn-{alias}
    HostName {private_ip}'''
public_entry = '''Host {alias}
    HostName {public_ip}'''


######################
### Terminal Funcs ###
######################

def get_args():
    '''
    parse command line arguments
    '''

    if len(sys.argv) != 2:
        print 'syntax error'
        print '{0} /path/to/config/file'.format(sys.argv[0])
        exit(1)

    return sys.argv[1]


def err(msg):
    '''
    Print error message to stderr
    '''

    print >> sys.stderr, msg


def print_host(data):
    '''
    Print the host entries in ssh_config format
    '''

    private_ip = data.pop('private_ip')
    public_ip = data.pop('public_ip')
    alias = data.pop('alias')
    for entry in [public_entry, private_entry]:
        try:
            print entry.format(
                alias=alias, public_ip=public_ip, private_ip=private_ip
            )
            for key, value in data.iteritems():
                print '    {0} {1}'.format(key, value)
            print ''
        except KeyError as e:
            err('bad host data')
            err(str(e))


##############
### Checks ###
##############

def check_instance__none(account, items, target):
    '''
    Always True
    '''

    return True


def check_instance__tag(account, items, target):
    '''
    Check if the {k: v} is in the instance tags
    '''

    # Type tag
    if target['type'] == 'tag' and target['name'] in items['tags']:
        if items['tags'][target['name']] == target['value']:
            return True
    return False


############
### Main ###
############

def read_config_file(filename):
    '''
    read the config file into a dict
    '''

    with open(filename, 'r') as f:
        ret = json.loads(f.read())
    return ret


def get_instances(awskey, awssec):
    '''
    get all the instances from Amazon with the specific keys
    '''

    ret = []
    for region in boto.ec2.regions():
        all_instances = []
        try:
            conn = boto.ec2.connect_to_region(region.name, aws_access_key_id=awskey, aws_secret_access_key=awssec)
            all_instances = conn.get_all_instances()
        except boto.exception.EC2ResponseError:
            err("Got EC2ResponseError")

        ret += [i for r in all_instances for i in r.instances]
        conn.close()

    return ret


def get_target(account, items, targets):
    '''
    Choose the correct target from the account
    '''

    for i, target in enumerate(targets):
        try:
            try:
                f = globals()['check_instance__{0}'.format(target['type'])]
            except AttributeError:
                err('"{0}" is not a valid check in account "{1}"'.format(account, target['type']))
                continue
            if f(account, items, target):
                return target
        except KeyError as e:
            err('missing "{2}" field in entry #{0} under account {1}'.format(i, account, e.message))
            continue
    return None


def compile_instance_data(instance, account, meta, defaults):
    '''
    Get the correct settings of the instance
    '''

    items = {
        'account': account,
        'tags': {},
        'id': instance.__dict__['id'],
        'public_dns': instance.__dict__['public_dns_name'],
        'private_dns': instance.__dict__['private_dns_name'],
        'keypair': instance.__dict__['key_name'],
    }

    for key, value in instance.__dict__['tags'].iteritems():
        items['tags'][key] = value.replace(' ', '_')

    ret = {
        'private_ip': instance.__dict__['private_ip_address'],
        'public_ip': instance.__dict__['ip_address'],
    }

    try:
        ret['alias'] = defaults['alias'].format(**items)
    except KeyError:
        ret['alias'] = '{account}-{id}'.format(**items)

    target = get_target(account, items, meta['targets'])
    if target is None:
        return ret

    if 'alias' in target:
        try:
            ret['alias'] = target['alias'].format(**items)
        except KeyError as e:
            err('bad alias {0} missing {1}'.format(target['alias'], e.message))
            pass

    for key, value in target['ssh_opts'].iteritems():
        ret.update({key: value})

    if 'ssh_opts' in defaults:
        for key, value in defaults['ssh_opts'].iteritems():
            if not key in target['ssh_opts']:
                ret.update({key: value})

    return ret


def main():
    '''
    Main
    '''

    config_file = get_args()

    try:
        settings = read_config_file(config_file)
    except IOError as e:
        print 'bad configuration file: {0}'.format(e)
        return 1

    for account, meta in settings['credentials'].iteritems():
        try:
            instances = get_instances(meta['key'], meta['secret'])
        except KeyError:
            err('missing aws credentials for {0}'.format(account))
            continue

        for instance in instances:
            if instance.state != 'running':
                err('instance {0} of account "{2}" is in "{1}" state'.format(
                    instance.id,
                    instance.state,
                    account
                ))
                continue
            data = compile_instance_data(
                instance, account, meta, settings['defaults']
            )
            print_host(data)


if __name__ == '__main__':
    exit(main())

