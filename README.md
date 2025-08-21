# Ansible Collection to manage Brocade FOS over ssh interface

This collection helps to manage older Brocade switches without REST API.
It works through SSH interface and executes commands directly on the switch.

## Prerequisites

- Ansible 2.15
- Python 3.10
- Linux
- paramiko (Python ssh module)

## Supported versions

Tested with FabricOS 7.4.x, 8.1.x, 8.2.x.

## Documentation

Use ansible-doc or search on https://galaxy.ansible.com.

## Modules

The following modules are available:

* enfence.fos.command

## Using the collection

### Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:
```bash
ansible-galaxy collection install enfence.fos
```

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:
```yaml
---
collections:
  - name: enfence.fos
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the `ansible` package. To upgrade the collection to the latest available version, run the following command:
```bash
ansible-galaxy collection install enfence.fos --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version `1.0.0`:

```bash
ansible-galaxy collection install enfence.fos:==1.0.0
```

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior, please refer to the [policy violations](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html#policy-violations) section of the Code for information on how to raise a complaint.

## Contributions

Contributions are welcome. Open an issue or create a pull request.

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.

The collection is based on [original code from Chip Copper](https://github.com/brocade/ansible-fos-command).
The original code's copyright:

Copyright: (c) 2020 Chip Copper <chip.copper@broadcom.com>
GNU General Public License v3.0+

