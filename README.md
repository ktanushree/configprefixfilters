# Prisma SDWAN Get Policy Info
This utility is used to configure Global Prefix Filters.

### Synopsis
This script can be used to create or update existing Global Prefix Filters, used by ZBFW & App definitions
Configuration data can be given in a CSV file where each column represents a prefix filter. If a prefix filter already exists, the script will automatically update the prefix filter with the new prefixes mentioned in the CSV. 

Users can use the **action** verb to control over how an existing prefix filter gets updated.

- **APPEND (default)**: Will append prefixes listed in the CSV to the existing prefix filter definition.

- **OVERWRITE:** Will overwrite the existing prefix filter definition with the prefix filters listed in the CSV

**Eg:** If **testfilter** is already created on the controller and contains prefixes 10.20.30.0/30, 10.20.40.0/30 and 10.20.50.0/30. 
CSV contains the prefix 10.20.60.0/30 under **testfilter**. 

**testfilter** on action **APPEND** will be updated to 10.20.30.0/30, 10.20.40.0/30, 10.20.50.0/30, 10.20.60.0/30

**testfilter** on action **OVERWRITE** will be updated to 10.20.60.0/30


### Requirements
* Active Prisma SDWAN Account
* Python >=3.6
* Python modules:
    * Prisma SDWAN (CloudGenix) Python SDK >= 5.5.3b1 - <https://github.com/CloudGenix/sdk-python>

### License
MIT

### Installation:
 - **Github:** Download files to a local directory, manually run `configprefixfilters.py`. 

### Examples of usage:
Create New Global Prefix Filters
```
./createprefixfilters.py -F data.csv
```

Add new prefixes to existing Global Prefix Filters 
```
./createprefixfilters.py -F data.csv -A APPEND
```

Overwrite existing Global Prefix Filters
```
./createprefixfilters.py -F data.csv -A OVERWRITE
```

### Help Text:
```angular2
TanushreeKamath:configprefixfilters tkamath$ ./configprefixfilters.py -h
usage: configprefixfilters.py [-h] [--controller CONTROLLER] [--insecure] [--email EMAIL] [--pass PASS] [--filename FILENAME] [--action ACTION] [--debug DEBUG]

CloudGenix: Config Prefix Filter.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com
  --insecure, -I        Disable SSL certificate and hostname verification

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -PW PASS
                        Use this Password instead of prompting

Prefix Filter CSV:
  CSV file containing prefix filters information

  --filename FILENAME, -F FILENAME
                        Name of the file with path.
  --action ACTION, -A ACTION
                        Action for existing Prefix Filters. 
                        APPEND will append prefixes to the existing list. 
                        OVERWRITE will overwrite with new values from the CSV

Debug:
  These options enable debugging output

  --debug DEBUG, -D DEBUG
                        Verbose Debug info, levels 0-2
TanushreeKamath:configprefixfilters tkamath$ 
```

### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


### For more info
 * Get help and additional Prisma SDWAN Documentation at <https://docs.paloaltonetworks.com/prisma/prisma-sd-wan.html>
