# pcap-maker
 

## Install
Setup for development environment
```
python3 -m venv venv
source venv/bin/activate
pip install -e .[dev]
```
Replace the pip command with this for production
```
pip install .
```

## Usage:

```
python3 -m pcap_maker.runner
```



## Unittests

```
pytest .
```

## Code reformatting

```
autopep8 --in-place --aggressive --aggressive pcap_maker/*py
```

```
black pcap_maker
```
## Code style
```
flake8 pcap_maker
```

```
pylint pcap_maker/*py
```


## CI tests
```
pip3 install tox
tox
```

