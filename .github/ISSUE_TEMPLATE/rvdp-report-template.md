---
name: RVD report template
about: Template to report a valid robot vulnerability

---

| Input      | Value  |
|---------|--------|
| Robot <or Robot component> | <required> |
| Vendor  | <optional>  |
| CVE ID  | <if exists>  |
| CWE ID  | <optional>  |
| RVSS Score (if applies)  | <required>      |
| RVSS Vector (if applies)| <<optional>e.g:RVSS:1.0/AV:_/AC:_/PR:_/UI:_/Y:_/S:_/C:_/I:_/A:_/H:_> |
| GitHub Account | <required> |
| Date Reported  | <<required>e.g:YYYY-MM-DD> |
| Date Updated   | <optional>     |
| Attack vector | <<required>e.g.: Local network> |

## Component

* Pick one: 
    * Software component: yes/no
    * Hardware component: yes/no
    * Robot: yes/no


## RVSS ([paper](https://arxiv.org/pdf/1807.10357.pdf)):

* Pick ATTACK VECTOR
    * Physical Isolated: yes/no
    * Physical Restricted: yes/no
    * Physical Public: yes/no
    * Local: yes/no
    * Internal Network: yes/no
    * Adjacent Network: yes/no
    * Remote Network: yes/no

* Pick ATTACK COMPLEXITY
    * High: yes/no
    * Low: yes/no

* PRIVILEGES REQUIRED
    * High: yes/no
    * Low: yes/no
    * None: yes/no

* USER INTERACTION
    * Required: yes/no
    * None: yes/no
    
* AGE
    * Unknown: yes/no
    * Zero Day: yes/no
    * 1 or less: yes/no
    * Less than 3: yes/no
    * More than 3: yes/no
    
* SCOPE
    * Unchanged: yes/no
    * Changed: yes/no
    
* CONFIDENTIALITY
    * None: yes/no
    * Low: yes/no
    * High: yes/no
    
* INTEGRITY
    * None: yes/no
    * Low: yes/no
    * High: yes/no
    
* AVAILABILITY
    * None: yes/no
    * Low: yes/no
    * High: yes/no
    
* SAFETY
    * Unknown: yes/no
    * None: yes/no
    * Environmental: yes/no
    * Human: yes/no

### Description:

<What is the vulnerability? Please, describe in clear steps, how to reproduce the issue.>
