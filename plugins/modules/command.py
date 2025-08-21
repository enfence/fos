#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2025, eNFence GmbH (info@power-devops.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# based on https://github.com/brocade/ansible-fos-command

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: command

short_description: This module enables SAN automation through the FOS CLI.

version_added: "1.0.0"

description:
    - This modules provides a mechanism for executing FOS commands via an Ansible task.
    - Each task will be a separate virtual terminal session.
    - One or more commands may be executed in each task.
    - Each command begins by sending the CLI command as it would be entered at a system prompt.
    - The module then waits for responses.  Each response is examined to see if it contains
    - the prompt, an exit string, or a dialog question.  An exit string is something other than the prompt that
    - indicates that the session should be ended.  An example of this is when the firmwaredownload
    - command is executed.  The system does not return to the prompt but instead returns a
    - response saying Rebooting. A dialog question is prompting for further user input.  A typical
    - example is when a command has additional required parameters that cannot be provided as
    - CLI flags or when the system is asking for confirmation a la "Are you sure you want to reboot?"
    - Returning to the prompt indicated that the command has completed.
    - The module includes a configurable timeout value so that if an unexpected response comes from
    - the switch, the module will not hang indefinately.
    - The module also provides the ability to indicate if the command has changed the state of the
    - switch.  Since some commands affirm on change and others affirm on no change, it is up to
    - the user to indicate when change has and has not occurred.  Brocade will be providing
    - examples for many commands to indicate which options should be used with which commands.

options:
    credential:
        description:
            - Credentials to login to the FC switch.
        required: True
        suboptions:
            fos_ip_addr:
                description:
                    - IP address or logical name of the switch to be managed.
                required: True
            fos_username:
                description:
                    - Account name under which commands should be run.
                required: True
            fos_password:
                description:
                    - Password for the account.
                    - If not specified, SSH key will be used.
                required: False
    timeout:
        description:
            - Overall expected timeout value for the CLI session in seconds.
        required: False
        default: 15
    login_delay:
        description:
            - Delay between session establishment and first expected response from the target
        required: False
        default: 5
    ssh_fingerprint:
        description:
            - Check SSH hostkey before connecting
        required: False
        default: True
    commands:
        description:
            - List of commands to be executed in this session.
        required: True
        type: list
        suboptions:
            cmd:
                description:
                    - CLI command exactly as it would appear at a system prompt.
                    - To reduce dialogs, as many flags and parameters should be included as possible.
                required: True
            prompts:
                description:
                    - List of prompts and responses for the interactive parts of the command.
                required: False
                type: list
                suboptions:
                    question:
                        description:
                            - Prompt string as displayed by the CLI typically captured in a screen scrape.
                            - This string should be unambigouous and differentiated from other prompts.
                        required: True
                    response:
                        description:
                            - Answer to the prompt.  A default response is indicated by "".
                        required: True
            start_state:
                description:
                    - Assumed values for returned failure and changed state variables.
                    - These values are returned if no result tests change them.
                required: False
                type: list
                suboptions:
                    flag:
                        description:
                            - State variable to be set
                        choices: ['failed', 'changed']
                        required: True
                    value:
                        description:
                            - State variable default value
                        type: boolean
                        required: True
                default:
                    - flag: changed
                      value: False
                    - flag: failed
                      value: False
            result_tests:
                description:
                    - List of tests to be run to determine changes in the failed or changed state
                required: False
                type: list
                suboptions:
                    test:
                        description:
                            - Prompt string as displayed by the CLI typically captured in a screen scrape.
                            - This string should be unambigouous and differentiated from other prompts.
                        required: True
                    flag:
                        description:
                            - State variable to be set
                        choices: ['failed', 'changed']
                        required: True
                    value:
                        description:
                            - State variable default value
                        type: boolean
                        required: True
            exit_tests:
                description:
                    - List of strings other than the standard prompt that would indicated command termination.
                required: False
            timeout:
                description:
                    - Timeout value for this command if it should be different than the global value.
                    - Depending on the situation, a particular command may require more or less time.
                required: False
                default: -1 indicating the global value should be used.


author: "Chip Copper (chip.copper@broadcom.com)"
'''

EXAMPLES = r'''
- name: run fos commands
  enfence.fos.command:
    credential:
      fos_username: {{ username}}
      fos_password: {{ password }}
      fos_ip_addr: {{ switch_ip_address }}
    commands:
      - cmd: timeout 30
        start_state:
          - flag: changed
            value: true

      - cmd: defzone --allaccess
        prompts:
          - question: Do you want to
            response: "yes"

      - cmd: cfgsave
        prompts:
          - question: Do you want to
            response: "yes"

      - cmd: dnsconfig --add -domain mydomain.com -serverip1 8.8.8.8 -serverip2 8.8.4.4

      - cmd: tstimezone America/Chicago

      - cmd: switchdisable

      - cmd: switchenable

      - cmd: 'portname -d "C.T.A.R"'

      - cmd: fabricprincipal --enable -p 0x03 -f

      - cmd: creditrecovmode --cfg onLrOnly

      - cmd: dlsset --enable -lossless

      - cmd: bannerset
        prompts:
          - question: Please input content of security banner
            response: "This is to demo the banner set command.\n."

      - cmd: ipfilter --clone ipv4_telnet_http -from default_ipv4
      - cmd: ipfilter --delrule ipv4_telnet_http -rule 2
      - cmd: ipfilter --addrule ipv4_telnet_http -rule 2 -sip any -dp 23 -proto tcp -act deny
      - cmd: ipfilter --activate ipv4_telnet_http 
      - cmd: ipfilter --show

      - cmd: snmpconfig --set systemgroup
        prompts:
          - question: sysDescr
            response: DemoSwitch
          - question: sysLocation
            response: San Jose
          - question: sysContact
            response: ""
          - question: authTrapEnabled
            response: "true"

      - cmd: auditcfg --class 1,2,3,4,5,8,9

      - cmd: syslogadmin --set -ip 10.155.2.151
'''

RETURN = r'''
messages:
  description: Log of the terminal session.
  returned: always
  type: list
  sample: 
    - "SW170_X6-4:FID128:admin> timeout 30"
    - "IDLE Timeout Changed to 30 minutes"
    - "The modified IDLE Timeout will be in effect after NEXT login"
    - "SW170_X6-4:FID128:admin> defzone --allaccess"
    - "You are about to set the Default Zone access mode to All Access"
    - "Do you want to set the Default Zone access mode to All Access ? (yes, y, no, n): [no] yes"
    - "defzone setting is same and nothing to update."
    - ""
    - "SW170_X6-4:FID128:admin>"
'''

from ansible.module_utils.basic import AnsibleModule
import paramiko
import time

def open_session(module, ip_address, username, password, fingerprint, messages, timeout):
    changed = False
    failed = False
    messages.append("")
    messages.append("SSH into " + ip_address)
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    if not fingerprint:
        ssh.set_missing_host_key_policy(paramiko.client.WarningPolicy())
    try:
        ssh.connect(ip_address, username=username, password=password, timeout=timeout)
    except paramiko.ssh_exception.AuthenticationException as exception:
        messages.append("invalid name/password")
        messages.append("Invalid session credentials: " +  str(exception))
        failed = True
        module.fail_json(msg="Invalid login credentials.", messages=messages)
        #return ssh, shell, changed, failed
    except BaseException as exception:
        messages.append("Login error: " +  str(exception))
        failed = True
        module.fail_json(msg="Login error.", messages=messages)
        #return ssh, shell, changed, failed

    shell = ssh.invoke_shell()
    shell.settimeout(timeout)

    return ssh, shell, changed, failed


def close_session(ssh_session):
    ssh_session.close()
    return


def send_characters(module, messages, shell, the_characters):
    try:
        shell.send(the_characters)
    except BaseException as exception:
        messages.append("Sending error. Characters: " + the_characters + "Exception: " + str(exception))
        failed = True
        module.fail_json(msg="Sending characters error: ", messages=messages, failed=failed)
    return


def get_prompt(module, messages, shell, login_delay):
    # Send a newline, wait for prompt, and flush everything up to this point (assuming motd, etc.)
    send_characters(module, messages, shell, "\n")
    time.sleep(login_delay)
    try:
        response = shell.recv(9999)
    except socket.timeout as exception:
        messages.append("Prompt timeout - Step 1: " +  str(exception))
        failed = True
        module.fail_json(msg="Prompt timeout - Step 1.", failed=failed)

    # Send another newline to get a fresh prompt
    send_characters(module, messages, shell, "\n")

    # This will be the \n from the send.
    try:
        response = shell.recv(1)
    except socket.timeout as exception:
        messages.append("Prompt timeout - Step 2: " +  str(exception))
        failed = True
        module.fail_json(msg="Prompt timeout - Step 2. ", failed=failed)

    # This will be the \n from the prompt to begin on a new line.
    try:
        response = shell.recv(1)
    except socket.timeout as exception:
        messages.append("Prompt timeout - Step 3: " +  str(exception))
        failed = True
        module.fail_json(msg="Prompt timeout - Step 3. ")

    # This should be the prompt
    try:
        response = shell.recv(9999).decode()
    except socket.timeout as exception:
        messages.append("Prompt timeout - Step 4:  " +  str(exception))
        failed = True
        module.fail_json(msg="Prompt timeout - Step 4. ")
    return str(response)


def receive_until_match(module, messages, shell, match_array, exit_array, prompt_change):
    response_buffer = ""
    index = -1

    found = False
    closed = False
    exited = False

    while not found and not closed and not exited:
        try:
            temp_buffer = shell.recv(9999).decode()
        except socket.timeout as exception:
            messages.append("Receive error.  Buffer: " + response_buffer + "Exception: " +  str(exception))

            failed = True
            messages.append(response_buffer.split("\r\n"))
            module.fail_json(msg="Receive timeout.", messages=messages, failed=failed)
        response_buffer += temp_buffer
        for i in range(len(match_array)):
            if match_array[i] in response_buffer:
                index = i
                found = True
                break
        if len(temp_buffer) == 0:
            closed = True
        for i in range(len(exit_array)):
            if exit_array[i] in response_buffer:
                exited = True
        if prompt_change:
            prompt_match = re.search("\n[a-zA-Z0-9_.-]*:?[a-zA-Z_0-9]*:[a-zA-Z_0-9_.-]*>", \
                response_buffer)
            if prompt_match is not None:
                new_prompt = prompt_match.group()[1:]
                exited = True
        else:
            new_prompt = None

    return index, response_buffer, exited, new_prompt


def cleanup_response(response_buffer):
    response_lines = response_buffer.split("\r\n")
    return response_lines


def run_module():
    fos_credentials_options = dict(
        fos_ip_addr=dict(type='str', required=True),
        fos_username=dict(type='str', required=True),
        fos_password=dict(type='str', required=False),
        https=dict(type='str', required=False, default=False)		# for compat with brocade.fos
    )
    
    prompt_options = dict(
        question=dict(type='str', required=True),
        response=dict(type='str', required=True),
    )

    result_test_options = dict(
        test=dict(type='str', required=True),
        flag=dict(type='str', required=True, choices=['failed', 'changed']),
        value=dict(type='bool', required=True),

    )

    start_state_options = dict(
        flag=dict(type='str', required=True, choices=['failed', 'changed']),
        value=dict(type='bool', required=True),
    )

    command_set_options = dict(
        cmd=dict(type='str', required=True),
        prompts=dict(type='list', elements='dict', options=prompt_options, default=[]),
        start_state=dict(type='list', elements='dict', options=start_state_options,
            default=[{"flag": "changed", "value": False}, {"flag": "failed", "value": False}]),
        result_tests=dict(type='list', elements='dict', options=result_test_options, default=[]),
        exit_tests=dict(type='list', elements='str', default=[]),
        timeout=dict(type='int', default=-1),
    )

    module_args = dict(
        credential=dict(type='dict', options=fos_credentials_options, required=True),
        timeout=dict(type='int', default=15),
        login_delay=dict(type='int', default=5),
        ssh_fingerprint=dict(type='bool', default=True),
        commands=dict(type='list', elements='dict', options=command_set_options, required=True)
    )

    result = dict(
        changed=False,
        rc=0
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    warnings = list()
    messages = list()

    changed = False
    failed = False

    prompt_change_commands = []
    prompt_change_commands.append("setcontext")

    result = {}

    # Establish session with switch
    ssh, shell, changed, failed = open_session(module, module.params['credential']['fos_ip_addr'],
        module.params['credential']['fos_username'], module.params['credential']['fos_password'],
        module.params['ssh_fingerprint'], messages, module.params['timeout'])

    # Discover prompt string
    switch_prompt = get_prompt(module, messages, shell, module.params['login_delay'])
    collected_responses = switch_prompt

    command_state = {'changed': False, 'failed': False}

    # For each command
    for command_index in range(len(module.params['commands'])):
        # Build the expected responses for each question or prompt
        questions = []
        cmd = module.params['commands'][command_index]
        # Set the individual command starting state
        for i in range(len(cmd['start_state'])):
            command_state[cmd['start_state'][i]['flag']] = cmd['start_state'][i]['value']

        if len(cmd['prompts']) > 0:
            for prompt_index in range(len(cmd['prompts'])):
                questions.append(cmd['prompts'][prompt_index]['question'])

        # Build the list of possible exit strings in addition to the prompt
        exit_array = list(cmd['exit_tests'])
        exit_array.append(switch_prompt)

        # Start the accumulated dialog with the command
        command_results = ""

        # Set the command specific timeout if one is indicated
        if cmd['timeout'] == -1:
            shell.settimeout(module.params['timeout'])
        else:
            shell.settimeout(cmd['timeout'])

        # If the command is in the prompt change list, set the flag.  Otherwise clear the flag
        prompt_change = False
        for i in range(len(prompt_change_commands)):
            if prompt_change_commands[i] in cmd['cmd']:
                prompt_change = True

        # Send the inital command line
        send_characters(module, messages, shell, cmd['cmd'] + "\n")

        # This loop will repeat until either the prompt or another exit string is found
        back_to_prompt = False
        while not back_to_prompt:
            prompt_index, response_buffer, exited, new_prompt = \
                receive_until_match(module, messages, shell, questions, exit_array, prompt_change)
            command_results += response_buffer
            if exited:
                back_to_prompt = True
                if prompt_change:
                    switch_prompt = new_prompt
            else:
                send_characters(module, messages, shell, cmd['prompts'][prompt_index]['response'] + "\n")

        for check_index in range(len(cmd['result_tests'])):
            if cmd['result_tests'][check_index]['test'] in command_results:
                command_state[cmd['result_tests'][check_index]['flag']] = cmd['result_tests'][check_index]['value']

        if command_state['changed'] is True:
            changed = True
        if command_state['failed'] is True:
            failed = True
        collected_responses += command_results

        # Look at final fail and changed state and update accordingly

    # End session and return
    #messages.append(cleanup_response(collected_responses))
    messages = cleanup_response(collected_responses)

    result['changed'] = changed
    result['failed'] = failed
    result['messages'] = messages
    result['warnings'] = warnings

    close_session(ssh)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()


