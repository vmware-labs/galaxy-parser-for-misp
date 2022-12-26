# Galaxy Parser for MISP

Utilities to parse galaxy clusters and resolve labels, including synonyms.

There are some string normalization steps (whitespace removal and compound words handling) that 
can be improved, but anything domain-specific is computed using MISP galaxies.

```bash
./bin/query_galaxy.py sednit -g mitre-intrusion-set 
> Mapping 'sednit' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py apt28 -g mitre-intrusion-set 
> Mapping 'apt28' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py feodo -g malpedia
> Mapping 'feodo' to:  ['misp-galaxy:malpedia="Emotet"']
```

```bash
./bin/query_galaxy.py emotet -g malpedia
> Mapping 'emotet' to:  ['misp-galaxy:malpedia="Emotet"']
```

There is also another script included: `update_cluster_tags.py`. This script 
tries to handle scenarios when MISP galaxies evolve over time.
For example clusters can be merged (because of new synonyms), or simply renamed
(e.g., a MITRE technique getting slightly renamed). When this happens galaxy tags
are not recognized anymore as such by the MISP instance, and instead they are visually
downgraded to local tags.

This script searches and promotes all downgraded tags to their former (galaxy) glory.
You can invoke it as follows (`-d` is a dry-run). Note that it requires accessing
a full fledge MISP installation, and thus requires a configuration file (template 
included).

```bash
./bin/update_cluster_tags.py -c ./data/config.ini
> Scanning tags
> Tag 'misp-galaxy:mitre-attack-pattern="Command-Line Interface - T1059"' should be replaced with 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'
> Tag 'misp-galaxy:mitre-attack-pattern="Group Policy Modification - T1484"' should be replaced with 'misp-galaxy:mitre-attack-pattern="Domain Policy Modification - T1484"'
> Tag 'misp-galaxy:mitre-attack-pattern="Standard Application Layer Protocol - T1071"' should be replaced with 'misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071"'
> Processing events
> [1/3] Replacing tag 'misp-galaxy:mitre-attack-pattern="Command-Line Interface - T1059"' with 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'
>        [1/1] Processing event 'Event 1 on ransomware'
> [2/3] Replacing tag 'misp-galaxy:mitre-attack-pattern="Group Policy Modification - T1484"' with 'misp-galaxy:mitre-attack-pattern="Domain Policy Modification - T1484"'
>        [1/1] Processing event 'Event 2 on ransomware'
> [3/3] Replacing tag 'misp-galaxy:mitre-attack-pattern="Standard Application Layer Protocol - T1071"' with 'misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071"'
>        [1/1] Processing event 'Event 3 on ransomware'
> Processing attributes
> [1/3] Replacing tag 'misp-galaxy:mitre-attack-pattern="Command-Line Interface - T1059"' with 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'
>        [1/65] Processing attribute '8f4f6c37-29c1-47fe-a144-32eb834370e6'
> ...
```

## Install

This package is available on PyPI, and it can be installed with `pip`:
```bash
pip install misp-galaxy-parser
```

To install and use the component requiring `pymisp` you just need to install
the package together with its `misp` extra (use quotes or double quotes if your
shell process square brackets):
```bash
pip install misp-galaxy-parser[misp]
```

## Development

We use `tox` to run tests (via `nose2`), `black` as formatter, and `pylint` as
static checker. You can install them (use a virtual environment) using `pip`:
```bash
python3 -m venv venv
source ./venv/bin/activate
pip install tox black pylint
```
And run them as follows:
```bash
tox
>  py39: OK (4.13=setup[3.98]+cmd[0.16] seconds)
>  congratulations :) (4.17 seconds)
```
```bash
pylint ./bin ./src ./tests
> 
> --------------------------------------------------------------------
> Your code has been rated at 10.00/10 (previous run: 10.00/10, +0.00)
> 
```
```bash
black ./bin ./src ./tests
> All done! ✨ 🍰 ✨
> 8 files left unchanged.
```

## Contributing

The galaxy-parser-for-misp project team welcomes contributions from the community. Before you start working with galaxy-parser-for-misp, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[BSD 2-Clause](https://spdx.org/licenses/BSD-2-Clause.html)
