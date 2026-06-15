## 1.0.0.0.57

* Fixed StrictMode regressions. Thanks to @i3laze for the bug report

## 1.0.0.0.56

* Added "-CollectLogs" feature.
* Fixed bug which caused only the last of four depots to be created in clean-slate environments (reported scenario: vCenter 8.0 U3g after `updatemgr-utility.py reset-db`).
* Fixed issue three `return` statements inside the depot create loop changed to `continue` so that a single depot failure does not abort processing of remaining depots. Thanks to @i3laze for the bug report
* Stale depot deletion failures now skip create rather than silently leaving the environment in a broken state; `$allDepots` is refreshed after each successful deletion to prevent stale state re-processing.
* Fixed `Invoke-SyncDepotsAsync` wrapped in `try/catch` with null task ID check; sync failures are now reported as warnings rather than logged as success

## 1.0.0.0.55

* Misc bug fixes to improve reliability

## 1.0.0.0.54

* Removed legacy VMware.PowerCLI 13.3 support (VCF.PowerCLI 9 now required).
* Added DEBUG log mode.
* Restructured for Strict mode support.
 
## 1.0.0.0.53

* Fixed issue with VCF.PowerCLI 9 support & VCF 9 detection.

## 1.0.0.0.52 

* Support for VCF.PowerCLI 9 & added -SkipVcenter feature.

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
