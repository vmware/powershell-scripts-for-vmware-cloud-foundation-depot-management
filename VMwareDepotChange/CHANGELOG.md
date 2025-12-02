## 1.0.0.0.54

* Removed legacy VMware.PowerCLI 13.3 support (VCF.PowerCLI 9 now required)
* Added DEBUG log mode
* Restructed for Strict mode support
 
## 1.0.0.0.53

* Fixed issue with VCF.PowerCLI 9 support & VCF 9 detection

## 1.0.0.0.52 

* Support for VCF.PowerCLI 9 & added -SkipVcenter Feature

## 1.0.0.0.51 

* Bugfix for error "Cannot validate argument on parameter 'NewDepotFqdn'"

## 1.0.0.0.50

* Added "-DryRun" option to check download token validity and depot reachability from script execution system.
* Added helpful error message for when script execution system does not trust SDDC manager's SSL certificate.
* Bug fix for authentication against isolated domains and SDDCm versions prior to 5.2.
* Bug fix for listing custom depots using check command.
* Removed "-Restore" option.

## 1.0.0.0.49 

* Added fixes for minor errors (e.g. message type prefaced with dash for INFO).

## 1.0.0.0.48 

* Support automation of proxy server validation configuration (KB392212).
