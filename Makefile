### Makefile --- 

## Author: shell@dsk
## Version: $Id: Makefile,v 0.0 2018/06/09 03:07:02 shell Exp $
## Keywords: 
## X-URL: 

buildenv:
	rm -rf pyenv
	virtualenv -p python3 pyenv
	pyenv/bin/pip install -r requirements.txt

### Makefile ends here
