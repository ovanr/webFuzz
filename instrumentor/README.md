# PHP-INSTRUMENTOR

Instrument PHP files using Node, Edge, Node-Edge (combo) or Path coverage policy.

Coverage feedback can be outputted in the form of a file or via HTTP headers.

## Usage

**Tested on PHP8.2.3**

1. Install needed libraries using composer:
```sh
composer install
```

2. Start instrumenting using:
```sh
php src/instrumentor.php --verbose --method (file|http) --policy (node|edge|...) --exclude exclude.txt --dir <root-of-webapp>
```

You can pass in a file to exclude which is a line separated list of paths 
that should not be instrumented.
If a folder name is provided then the contents of the whole folder will not
be instrumented

3. Create instrumentation output folder and update permissions:
```sh
sudo mkdir /var/instr
sudo chmod o+rwx /var/instr
```

## Authors

* **Orpheas van Rooij** - *orpheas.vanrooij@outlook.com*

## License

[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
