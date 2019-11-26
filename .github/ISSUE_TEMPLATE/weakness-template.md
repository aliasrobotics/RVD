---
name: Weakness report template
about: Template to report a weakness in RVD. See https://bit.ly/2JnamaD if in doubt
title: ''
labels: weakness, triage
assignees: ''

---

Fill in following the example below. If you need further clarifications on any of the items, refer to our [taxonomy](https://github.com/aliasrobotics/RVD/blob/master/docs/TAXONOMY.md) (remove these lines line).

```yaml
{
    "id": 508,
    "title": "rcl_action: data race, eprosima::fastrtps::rtps::Participant...",
    "type": "weakness",
    "description": "Issue detected while running Google Sanitizers.\n\n ",
    "cwe": "None",
    "cve": "None",
    "keywords": [
        "components software",
        "master",
        "package: rcl_action",
        "robot component: ROS2",
        "weakness"
    ],
    "system": "ros2",
    "vendor": "N/A",
    "severity": {
        "rvss-score": "None",
        "rvss-vector": "N/A",
        "severity-description": "",
        "cvss-score": 0,
        "cvss-vector": ""
    },
    "links": [
        "https://github.com/aliasrobotics/RVD/issues/508"
    ],
    "flaw": {
        "phase": "testing",
        "specificity": "ROS-specific",
        "architectural-location": "platform code",
        "application": "N/A",
        "subsystem": "cognition:ros2",
        "package": "rcl_action",
        "languages": "None",
        "date-detected": "Mon, 21 Oct 2019 07:39:17 +0000",
        "detected-by": "",
        "detected-by-method": "testing dynamic",
        "date-reported": "Mon, 21 Oct 2019 07:39:17 +0000",
        "reported-by": "Alias Robotics (http://aliasrobotics.com)",
        "reported-by-relationship": "automatic",
        "issue": "https://github.com/aliasrobotics/RVD/issues/508",
        "reproducibility": "always",
        "trace": null,
        "reproduction": "Find a    pre-compiled environment in the Docker image below. Reproducing it implies    source the workspace, finding the appropriate test and executing it.",
        "reproduction-image": "registry.gitlab.com/aliasrobotics/offensive/alurity/ros2/ros2:build-tsan2-commit-b2dca472a35109cece17d3e61b18af5cb9be5772"
    },
    "exploitation": {
        "description": "",
        "exploitation-image": "",
        "exploitation-vector": ""
    },
    "mitigation": {
        "description": "",
        "pull-request": ""
    }
}
```