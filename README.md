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
./pcap_maker/runner.py
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


## CI tests
```
pip3 install tox
tox
```

