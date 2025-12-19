# pcap-maker
 

## Install
Setup 
```
python3 -m venv venv
source venv/bin/activate
```

```
pip3 install -r requirements.txt
```

## Usage:

```
python3 -m pcap_maker.runner
```



## Unittests

```
pip3 install pytest
pytest .
```

## Code reformatting

```
pip3 install autopep8
autopep8 --in-place --aggressive --aggressive pcap_maker/*py
```

```
pip3 install black
black pcap_maker
```
## Code style
```
pip3 install flake8
flake8 pcap_maker
```

```
pip3 install pylint
pylint pcap_maker/*py
```


## CI tests
```
pip3 install tox
tox
```

