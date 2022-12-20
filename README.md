# Galaxy Parser for MISP

Utilities to parse galaxy clusters and resolve labels (including synonyms).

There is some string normalization (whitespace removal and compound words handling) that 
can be improved, but anything domain-specific is computed using MITRE galaxies.

```bash
./bin/query_galaxy.py -q sednit -g mitre-intrusion-set 
> Mapping 'sednit' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py -q apt28 -g mitre-intrusion-set 
> Mapping 'apt28' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py -q feodo -g malpedia
> Mapping 'feodo' to:  ['misp-galaxy:malpedia="Emotet"']
```

```bash
./bin/query_galaxy.py -q emotet -g malpedia
> Mapping 'emotet' to:  ['misp-galaxy:malpedia="Emotet"']
```

## Contributing

The galaxy-parser-for-misp project team welcomes contributions from the community. Before you start working with galaxy-parser-for-misp, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[BSD 2-Clause](https://spdx.org/licenses/BSD-2-Clause.html)
