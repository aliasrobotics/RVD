---
name: Exposure report template
about: Template to report a exposure in RVD. See https://bit.ly/2JnamaD if in doubt
title: ''
labels: exposure
assignees: ''

---

Fill in following the example below. If you need further clarifications on any of the items, refer to our [taxonomy](https://github.com/aliasrobotics/RVD/blob/master/docs/TAXONOMY.md) (remove these lines line).

```yaml
id: N/A (pending)
title: Defaults lead to information exposure
type: weakness
description: Due to a missconfigufation of the defaults, ROS 2 node information is by default shared in plain across the ROS 2 graph.
cwe: CWE-200 (Information Exposure)
cve: None
keywords: ['defaults', 'ROS 2', 'SROS2', 'information disclosure']
system: ros2
vendor: Open Robotics
severity:
  rvss_score: None
  rvss_vector: None
  severity_description: None
  cvss_score: None
  cvss_vector: None
links: ['https://github.com/ros2/sros2/blob/master/sros2/sros2/policy/defaults/dds/governance.xml#L13']
flaw:
  phase: runtime-operation
  specificity: ROS-specific
  architectural-location: platform code
  application: security of middleware communications
  subsystem: communication:ros2:dds:sros2
  package: turtlebot/turtlebot/turtlebot_bringup | turtlebot/turtlebot/turtlebot_capabilities
  languages: XML
  date-detected: N/A (pending)
  detected-by: Alias Robotics
  detected-by-method: runtime detection
  date-reported: N/A (pending)
  reported-by: Alias Robotics
  reported-by-relationship: security researcher
  issue: N/A (pending)
  reproducibility: always
  trace: N/A
  reproduction: None (pending)    	
  reproduction-image: None (pending)    	
exploitation:
  description: None (pending)
  exploitation-image: None (pending)
  exploitation-vector: None (pending)
mitigation:
  description: None
  pull-request: None
```
